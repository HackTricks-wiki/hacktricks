# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인 by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Run HackTricks Locally
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
Your local copy of HackTricks will be **[http://localhost:3337](http://localhost:3337)**에서 **5분 이내에 사용 가능**합니다(책을 빌드해야 하므로 잠시 기다려 주세요).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 **HACK THE UNHACKABLE**을 슬로건으로 내세우는 훌륭한 cybersecurity 회사입니다. 이들은 자체 연구를 수행하고 자체 hacking tools를 개발하여 **pentesting, Red teams, training** 같은 여러 가치 있는 cybersecurity 서비스를 제공합니다.

그들의 **blog**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 HackTricks 같은 cybersecurity open source 프로젝트도 지원합니다 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **유럽 1위** ethical hacking 및 **bug bounty platform**입니다.

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에 참여해 bounties로 최대 **$100,000**까지 벌어보세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 **engineering-first, hands-on lab approach**를 바탕으로 **실용적인 AI Security training**을 제공합니다. 우리의 과정은 security engineers, AppSec professionals, 개발자들이 **실제 AI/LLM-powered applications를 만들고, 깨고, 보호**할 수 있도록 구성되어 있습니다.

**AI Security Certification**은 다음을 포함한 실제 기술에 중점을 둡니다:
- LLM 및 AI-powered applications 보안
- AI systems에 대한 threat modeling
- Embeddings, vector databases, RAG security
- LLM attacks, abuse scenarios, practical defenses
- Secure design patterns 및 deployment considerations

모든 과정은 **on-demand**, **lab-driven**이며, 단순한 이론이 아니라 **실제 security tradeoffs**를 중심으로 설계되었습니다.

👉 AI Security course에 대한 자세한 내용:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 **search engine results**에 빠르고 쉽게 접근할 수 있는 실시간 API를 제공합니다. 이들은 search engines를 스크래핑하고, proxies를 처리하고, captchas를 해결하고, 모든 rich structured data를 파싱해 줍니다.

SerpApi 요금제 구독에는 Google, Bing, Baidu, Yahoo, Yandex 등 50개가 넘는 다양한 search engines 스크래핑용 API 접근이 포함됩니다.\
다른 제공업체와 달리, **SerpApi는 단순히 organic results만 스크래핑하지 않습니다**. SerpApi 응답에는 광고, 인라인 이미지와 비디오, knowledge graphs, 그리고 search results에 있는 다른 요소와 기능이 일관되게 포함됩니다.

현재 SerpApi 고객에는 **Apple, Shopify, GrubHub**가 있습니다.\
자세한 정보는 [**blog**](https://serpapi.com/blog/)**,** 또는 [**playground**](https://serpapi.com/playground)**.**에서 예제를 확인해 보세요.\
[**여기**](https://serpapi.com/users/sign_up)**에서 무료 계정을 생성**할 수 있습니다.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**는 활발히 활동하는 researchers가 가르치는 offensive mobile 및 AI security를 훈련합니다. 이들은 CVE writeups와 Black Hat, HITB, Zer0con 발표를 맡아온 동일한 팀입니다. 과정은 자기 주도형이며, 실제 target의 labs를 중심으로 구성되고, hands-on certification이 지원됩니다.

카탈로그는 두 트랙으로 구성됩니다:

**Mobile Security** – iOS와 Android를 app layer부터 깊게 다룹니다: Ghidra와 LLDB를 이용한 reverse engineering, ARM64 exploitation, kernel internals와 현대적 mitigations(PAC, MTE, SELinux), jailbreak 및 rooting mechanics.

**AI Security** – 이 분야 전반을 아우르는 두 개의 완전한 과정. Practical AI Security는 LLMs, RAG pipelines, AI agents, MCP의 동작 방식과 이를 공격하고 방어하는 방법을 다룹니다. Advanced AI Security는 최전선에서 더 빌드 중심으로 진행되며, Garak과 PyRIT로 대규모 AI systems red teaming, MCP servers exploitation, model backdoors 심기 및 탐지, Apple Silicon에서의 fine-tuning attacks와 defenses를 다룹니다.

과정 및 인증:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**는 공격자가 먼저 찾기 전에 exploitable vulnerabilities를 찾아내는 AI-powered security platform입니다.

**Code security tip**: 개발자와 security teams를 위해 만들어진 스마트 vulnerability monitoring platform NaxusAI에 **sign up**하세요! 오늘 함께하고, AI를 사용해 **production에 도달하기 전에 실제 security risks를 detecting, validating, and fixing**해 보세요!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **Amsterdam**에 본사를 둔 전문 cybersecurity 회사로, **modern**한 접근 방식의 **offensive-security services**를 제공하여 전 세계의 기업을 최신 cybersecurity threats로부터 **보호**하는 데 도움을 줍니다.

WebSec는 Amsterdam과 Wyoming에 사무소를 둔 국제 보안 회사입니다. 이들은 **all-in-one security services**를 제공하며, Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등 모든 것을 수행합니다.

WebSec의 또 다른 멋진 점은 업계 평균과 달리 WebSec가 자신의 실력에 **매우 자신감이 있다**는 것이며, 그 정도가 **최고 품질의 결과를 보장**한다고 말할 만큼입니다. 웹사이트에는 "**If we can't hack it, You don't pay it!**"라고 적혀 있습니다. 자세한 정보는 [**website**](https://websec.net/en/)와 [**blog**](https://websec.net/blog/)를 확인해 보세요!

위 내용 외에도 WebSec는 HackTricks의 **헌신적인 후원자**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**현장에 맞게. 당신을 중심으로.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 설계하고 이끄는 효과적인 cybersecurity training을 개발하고 제공합니다. 이들의 프로그램은 이론을 넘어 팀에 깊은 이해와 실행 가능한 기술을 제공하며, 실제 threats를 반영한 custom environments를 사용합니다. 맞춤형 training 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**이들의 training을 돋보이게 하는 점:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **Education** 및 **FinTech** 기관을 위한 전문 cybersecurity services를 제공하며, **penetration testing, cloud security assessments**, **compliance readiness**(SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 우리 팀에는 **OSCP 및 CISSP certified professionals**가 포함되어 있어, 모든 engagement에 깊은 technical expertise와 industry-standard insight를 제공합니다.

우리는 high-stakes environments에 맞춘 **manual, intelligence-driven testing**으로 자동화된 스캔을 넘어섭니다. 학생 기록 보호부터 금융 거래 보호까지, 조직이 가장 중요한 것을 지킬 수 있도록 돕습니다.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

최신 cybersecurity 소식을 확인하고 업데이트를 유지하려면 [**blog**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps, 개발자가 Kubernetes clusters를 효율적으로 관리, 모니터링, 보호할 수 있게 해줍니다. AI-driven insights, advanced security framework, 직관적인 CloudMaps GUI를 활용해 clusters를 시각화하고, 상태를 이해하며, 자신 있게 대응하세요.

또한 K8Studio는 **모든 주요 kubernetes distributions**(AWS, GCP, Azure, DO, Rancher, K3s, Openshift 등)와 호환됩니다.

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
