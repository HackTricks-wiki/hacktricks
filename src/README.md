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

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 **HACK THE UNHACKABLE**이라는 슬로건을 가진 훌륭한 사이버보안 회사입니다. 이들은 자체 연구를 수행하고 자체 hacking tools를 개발하여 **pentesting, Red teams, training** 같은 여러 가치 있는 사이버보안 서비스를 **제공**합니다.

그들의 **blog**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 HackTricks와 같은 사이버보안 오픈소스 프로젝트도 지원합니다 :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **유럽 1위** ethical hacking 및 **bug bounty platform**입니다.

**Bug bounty tip**: **hackers에 의해, hackers를 위해 만들어진 프리미엄 bug bounty platform**인 **Intigriti**에 **sign up**하세요! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에 참여하고, 최대 **$100,000**까지의 bounties를 벌기 시작하세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

경험 많은 hackers와 bug bounty hunters와 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

- **Hacking Insights:** hacking의 짜릿함과 도전을 깊이 있게 다루는 콘텐츠와 함께하세요
- **Real-Time Hack News:** 실시간 뉴스와 인사이트를 통해 빠르게 움직이는 hacking 세계를 최신 상태로 유지하세요
- **Latest Announcements:** 새로 시작되는 bug bounties와 중요한 platform 업데이트를 가장 먼저 확인하세요

**[**Discord**](https://discord.com/invite/N3FrSbmwdy)에서 우리와 함께하고 오늘 바로 최고의 hackers들과 협업을 시작하세요!**

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 **engineering-first, hands-on lab approach**를 바탕으로 한 **실용적인 AI Security training**을 제공합니다. 우리의 코스는 security engineers, AppSec professionals, developers가 **실제 AI/LLM-powered applications를 build, break, secure**할 수 있도록 설계되었습니다.

**AI Security Certification**은 다음을 포함한 실제 환경 기술에 중점을 둡니다:
- LLM 및 AI-powered applications 보안
- AI systems에 대한 threat modeling
- Embeddings, vector databases, 및 RAG 보안
- LLM attacks, abuse scenarios, 그리고 실용적인 방어
- Secure design patterns 및 deployment 고려사항

모든 코스는 **on-demand**, **lab-driven**이며, 단순한 이론이 아니라 **real-world security tradeoffs**를 중심으로 설계되었습니다.

👉 AI Security course에 대한 자세한 내용:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 **search engine results에 접근**할 수 있는 빠르고 쉬운 real-time APIs를 제공합니다. 이들은 search engines를 스크래핑하고, proxies를 처리하며, captchas를 해결하고, 모든 풍부한 구조화 데이터를 파싱해 줍니다.

SerpApi의 요금제 중 하나를 구독하면 Google, Bing, Baidu, Yahoo, Yandex 등 다양한 search engines를 스크래핑할 수 있는 50개 이상의 서로 다른 APIs에 접근할 수 있습니다.\
다른 제공업체와 달리, **SerpApi는 단순히 organic results만 스크래핑하지 않습니다**. SerpApi 응답에는 광고, inline images와 videos, knowledge graphs, 그리고 search results에 포함된 다른 요소와 기능이 항상 함께 포함됩니다.

현재 SerpApi 고객에는 **Apple, Shopify, and GrubHub**가 있습니다.\
자세한 내용은 [**blog**](https://serpapi.com/blog/)**,** 또는 [**playground**](https://serpapi.com/playground)**.**에서 예제를 확인하세요.\
[**here**](https://serpapi.com/users/sign_up)**.**에서 **free account**를 만들 수 있습니다.

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

모바일 애플리케이션과 디바이스를 보호하기 위해 vulnerability research, penetration testing, reverse engineering을 수행하는 데 필요한 기술과 역량을 배우세요. 온디맨드 코스와 **get certified**를 통해 **iOS and Android security**를 마스터하세요:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **Amsterdam**에 기반을 둔 전문 사이버보안 회사로, **modern**한 접근 방식의 **offensive-security services**를 제공하여 전 세계 비즈니스를 최신 사이버보안 위협으로부터 **보호**하는 데 도움을 줍니다.

WebSec는 Amsterdam과 Wyoming에 사무실을 둔 국제 보안 회사입니다. 이들은 **all-in-one security services**를 제공하며, 이는 Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등 모든 것을 한다는 뜻입니다.

WebSec의 또 다른 멋진 점은 업계 평균과 달리 WebSec가 자신의 역량에 **매우 자신감**이 있다는 것이며, 그 정도가 **최고 품질의 결과를 보장**할 정도입니다. 웹사이트에는 "**If we can't hack it, You don't pay it!**"라고 적혀 있습니다. 더 많은 정보는 [**website**](https://websec.net/en/)와 [**blog**](https://websec.net/blog/)를 확인하세요!

위 내용에 더해 WebSec는 HackTricks의 **헌신적인 지지자**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**현장을 위해 만들어졌습니다. 당신을 중심으로 만들어졌습니다.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 구축하고 이끄는 효과적인 사이버보안 training을 개발하고 제공합니다. 이들의 프로그램은 이론을 넘어, 실제 위협을 반영한 custom environments를 사용하여 팀에 깊은 이해와 실행 가능한 기술을 제공합니다. custom training 문의는 [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**그들의 training을 차별화하는 요소:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **Education** 및 **FinTech** 기관을 위한 전문 사이버보안 서비스를 제공하며, 특히 **penetration testing, cloud security assessments**, 그리고 **compliance readiness**(SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 우리 팀에는 **OSCP and CISSP 인증 전문가**가 포함되어 있으며, 모든 업무에 깊은 기술적 전문성과 업계 표준 수준의 통찰을 제공합니다.

우리는 고위험 환경에 맞춘 **manual, intelligence-driven testing**으로 자동화된 스캔을 넘어섭니다. 학생 기록 보호부터 금융 거래 보호까지, 조직이 가장 중요한 것을 방어할 수 있도록 돕습니다.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

최신 사이버보안 소식을 확인하고 최신 정보를 유지하려면 [**blog**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps, developers가 Kubernetes clusters를 효율적으로 관리, 모니터링, 보호할 수 있도록 지원합니다. 우리의 AI-driven insights, advanced security framework, 직관적인 CloudMaps GUI를 활용하여 clusters를 시각화하고, 상태를 이해하며, 자신 있게 대응하세요.

또한 K8Studio는 **모든 주요 kubernetes distributions**(AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more)과 호환됩니다.

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
