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
Your local copy of HackTricks will be **[http://localhost:3337](http://localhost:3337)**에서 **5분 이내에 사용 가능**합니다(책을 빌드해야 하므로, 잠시 기다려 주세요).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 **HACK THE UNHACKABLE**이라는 슬로건을 가진 뛰어난 cybersecurity 회사입니다. 이들은 자체 연구를 수행하고 자체 hacking tools를 개발하여 **pentesting**, Red teams, training 같은 여러 유용한 cybersecurity 서비스를 **제공**합니다.

그들의 **blog**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다

**STM Cyber**는 HackTricks 같은 cybersecurity open source projects도 지원합니다 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **Europe의 #1** ethical hacking 및 **bug bounty platform**입니다.

**Bug bounty tip**: **Intigriti**에 **sign up**하세요, 해커가 해커를 위해 만든 프리미엄 **bug bounty platform**입니다! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 함께하고, 최대 **$100,000**까지 bounties를 벌기 시작하세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

경험 많은 hackers와 bug bounty hunters와 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

- **Hacking Insights:** hacking의 스릴과 도전을 깊이 있게 다루는 콘텐츠와 함께해 보세요
- **Real-Time Hack News:** 실시간 news와 insights를 통해 빠르게 변하는 hacking world를 최신 상태로 유지하세요
- **Latest Announcements:** 새로 시작되는 bug bounties와 중요한 platform 업데이트를 확인하세요

오늘 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에서 함께하고 top hackers와 협업을 시작하세요!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 **engineering-first, hands-on lab approach**를 기반으로 한 **실전 AI Security training**을 제공합니다. 우리의 course는 security engineers, AppSec professionals, developers가 **실제 AI/LLM-powered applications를 build, break, and secure**하도록 설계되었습니다.

**AI Security Certification**은 다음을 포함한 실전 기술에 중점을 둡니다:
- LLM 및 AI-powered applications 보안
- AI systems에 대한 threat modeling
- Embeddings, vector databases, 및 RAG security
- LLM attacks, abuse scenarios, 및 실용적 defenses
- Secure design patterns 및 deployment considerations

모든 course는 **on-demand**이며, **lab-driven**이고, 단순한 이론이 아니라 **실제 security tradeoffs**를 중심으로 설계되었습니다.

👉 AI Security course의 자세한 내용:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 search engine results에 **접근**하기 위한 빠르고 쉬운 real-time APIs를 제공합니다. 이들은 search engines를 scrape하고, proxies를 처리하며, captchas를 풀고, 모든 rich structured data를 파싱해 줍니다.

SerpApi의 plan 중 하나를 구독하면 Google, Bing, Baidu, Yahoo, Yandex 등을 포함해 다양한 search engine scraping용 50개 이상의 서로 다른 APIs에 접근할 수 있습니다.\
다른 providers와 달리, **SerpApi는 단순히 organic results만 scrape하지 않습니다**. SerpApi의 responses에는 광고, inline images와 videos, knowledge graphs, 그리고 search results에 있는 다른 요소와 기능이 항상 포함됩니다.

현재 SerpApi 고객에는 **Apple, Shopify, GrubHub**가 있습니다.\
자세한 내용은 [**blog**](https://serpapi.com/blog/)**,** 또는 [**playground**](https://serpapi.com/playground)**에서 예제를 확인해 보세요.**\
[**here**](https://serpapi.com/users/sign_up)에서 **free account**를 **create**할 수 있습니다.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

모바일 applications과 devices를 보호하기 위해 vulnerability research, penetration testing, reverse engineering에 필요한 technologies와 skills를 배워 보세요. 우리의 on-demand course를 통해 **iOS 및 Android security를 마스터**하고 **인증**을 받으세요:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**는 공격자보다 먼저 exploitable vulnerabilities를 찾아내는 AI-powered security platform입니다.

**Code security tip**: 개발자와 security teams를 위해 만든 스마트 vulnerability monitoring platform인 NaxusAI에 sign up하세요! 오늘 함께해서 production에 도달하기 전에 **실제 security risks를 detecting, validating, and fixing**하는 데 AI를 사용해 보세요!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **Amsterdam**에 기반을 둔 전문 cybersecurity 회사로, **modern**한 접근 방식의 **offensive-security services**를 제공하여 전 세계 기업들이 최신 cybersecurity threats로부터 **보호**받도록 돕습니다.

WebSec는 Amsterdam과 Wyoming에 사무소를 둔 국제 security company입니다. 이들은 **all-in-one security services**를 제공하며, 이는 Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등 모든 것을 한다는 뜻입니다.

WebSec의 또 다른 멋진 점은 업계 평균과 달리 WebSec가 자신의 실력에 **매우 자신감**이 있다는 것이며, 그 정도가 **최고 품질의 결과를 보장**한다는 수준입니다. 웹사이트에는 "**If we can't hack it, You don't pay it!**"라고 적혀 있습니다. 더 자세한 정보는 [**website**](https://websec.net/en/)와 [**blog**](https://websec.net/blog/)를 확인해 보세요!

위 내용 외에도 WebSec는 HackTricks의 **헌신적인 supporter**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**현장에 맞게. 당신을 중심으로.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 설계하고 이끄는 효과적인 cybersecurity training을 개발하고 제공합니다. 이들의 program은 theory를 넘어, real-world threats를 반영한 custom environments를 사용해 teams에 깊은 이해와 실행 가능한 skills를 제공합니다. 맞춤 training 문의는 [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**이들의 training이 다른 점:**
* 맞춤 제작된 content와 labs
* 최고 수준의 tools와 platforms 기반
* 실무자들이 설계하고 강의

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **Education** 및 **FinTech** 기관을 위한 전문 cybersecurity services를 제공하며, 특히 **penetration testing, cloud security assessments**와 **compliance readiness**(SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 우리의 team은 **OSCP 및 CISSP certified professionals**로 구성되어 있으며, 모든 engagement에 깊은 technical expertise와 industry-standard insight를 제공합니다.

우리는 고위험 환경에 맞춰 **manual, intelligence-driven testing**으로 자동화된 scans를 넘어섭니다. 학생 기록 보호부터 금융 거래 보호까지, 조직이 가장 중요한 것을 방어하도록 돕습니다.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

최신 cybersecurity 소식을 확인하고 업데이트를 받으려면 [**blog**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps, developers가 Kubernetes clusters를 효율적으로 관리, 모니터링, 보안 강화할 수 있도록 지원합니다. AI-driven insights, advanced security framework, 그리고 직관적인 CloudMaps GUI를 활용해 clusters를 시각화하고, 상태를 이해하며, 확신 있게 대응하세요.

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

{{#include ./banners/hacktricks-training.md}}
