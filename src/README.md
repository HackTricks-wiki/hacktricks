# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 & 모션 디자인 by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks will be **http://localhost:3337**에서 **5분 이내에 이용 가능**합니다(책을 빌드해야 하므로 기다려 주세요).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 **HACK THE UNHACKABLE**를 슬로건으로 내세우는 훌륭한 사이버보안 회사입니다. 이들은 자체 연구를 수행하고 자체 해킹 도구를 개발하여 **pentesting, Red team 및 training 같은 여러 가치 있는 사이버보안 서비스**를 제공합니다.

그들의 **blog**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 HackTricks 같은 사이버보안 오픈소스 프로젝트도 지원합니다 :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **유럽 1위** ethical hacking 및 **bug bounty platform**입니다.

**Bug bounty tip**: **sign up** for **Intigriti**, 해커들이 해커들을 위해 만든 프리미엄 **bug bounty platform**! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에 가입하고, 최대 **$100,000**의 보상을 받기 시작하세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

경험 많은 해커와 bug bounty hunter들과 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

- **Hacking Insights:** hacking의 흥분과 도전을 깊이 있게 다루는 콘텐츠와 교류하세요
- **Real-Time Hack News:** 실시간 뉴스와 인사이트로 빠르게 변하는 hacking 세계를 최신 상태로 유지하세요
- **Latest Announcements:** 새로 시작되는 bug bounties와 중요한 플랫폼 업데이트를 확인하세요

오늘 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에서 함께하고 최상위 해커들과 협업을 시작하세요!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 **엔지니어링 우선, 실습 중심 랩 접근 방식**으로 **실용적인 AI Security training**을 제공합니다. 우리의 과정은 security engineer, AppSec 전문가, 그리고 **실제 AI/LLM 기반 애플리케이션을 build, break, secure**하고 싶은 개발자를 위해 만들어졌습니다.

**AI Security Certification**은 다음을 포함한 실무 역량에 중점을 둡니다:
- LLM 및 AI-powered 애플리케이션 보호
- AI 시스템의 threat modeling
- Embeddings, vector databases, 그리고 RAG security
- LLM attacks, abuse scenarios, 및 실용적인 방어
- 안전한 설계 패턴과 배포 고려사항

모든 과정은 **on-demand**, **lab-driven**이며, 단순한 이론이 아니라 **실제 보안 트레이드오프**를 중심으로 설계되었습니다.

👉 AI Security course에 대한 자세한 내용:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 **search engine results에 접근**할 수 있는 빠르고 쉬운 실시간 API를 제공합니다. 이들은 search engine을 scrape하고, proxy를 처리하며, captcha를 해결하고, 모든 rich structured data를 파싱해 줍니다.

SerpApi의 플랜 하나를 구독하면 Google, Bing, Baidu, Yahoo, Yandex 등 다양한 search engine을 위한 50개 이상의 서로 다른 scraping API에 접근할 수 있습니다.\
다른 제공업체와 달리, **SerpApi는 단순히 organic results만 scrape하지 않습니다**. SerpApi 응답에는 광고, inline images 및 videos, knowledge graphs, 그리고 search results에 있는 다른 요소와 기능이 일관되게 모두 포함됩니다.

현재 SerpApi 고객에는 **Apple, Shopify, GrubHub**가 있습니다.\
더 많은 정보는 [**blog**](https://serpapi.com/blog/)**,** 또는 [**playground**](https://serpapi.com/playground)**에서 예제를 확인해 보세요.**\
[**여기**](https://serpapi.com/users/sign_up)에서 **free account**를 만들 수 있습니다.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

모바일 애플리케이션과 디바이스를 보호하기 위한 vulnerability research, penetration testing, reverse engineering에 필요한 기술과 역량을 배우세요. **iOS and Android security**를 on-demand course로 마스터하고 **certified**를 받으세요:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI**는 공격자가 찾기 전에 exploit 가능한 vulnerabilities를 찾아내는 AI-powered security platform입니다.

**Code security tip**: 개발자와 security team을 위해 만들어진 스마트 vulnerability monitoring platform인 NaxusAI에 sign up하세요! 오늘 가입하고 AI를 사용해 **실제 security risks를 production에 도달하기 전에 detect, validate, fix**하기 시작하세요!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **Amsterdam**에 본사를 둔 전문 사이버보안 회사로, **modern**한 접근 방식의 **offensive-security services**를 제공하여 **전 세계**의 기업들이 최신 사이버보안 위협으로부터 **보호**할 수 있도록 돕습니다.

WebSec는 Amsterdam과 Wyoming에 사무소를 둔 국제 보안 회사입니다. 이들은 **all-in-one security services**를 제공하며, 즉 Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등 모든 것을 수행합니다.

WebSec의 또 다른 멋진 점은 업계 평균과 달리 WebSec가 자신의 실력에 **매우 자신 있다**는 것입니다. 그 정도로 **최고 품질의 결과를 보장**하며, 웹사이트에는 "**If we can't hack it, You don't pay it!**"라고 적혀 있습니다. 더 많은 정보는 [**website**](https://websec.net/en/)와 [**blog**](https://websec.net/blog/)를 확인하세요!

위 내용 외에도 WebSec는 HackTricks의 **헌신적인 지지자**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**현장에 맞게 설계. 당신을 중심으로 설계.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 만들고 이끄는 효과적인 사이버보안 training을 개발하고 제공합니다. 이들의 프로그램은 이론을 넘어, 실제 환경을 반영한 맞춤형 환경을 사용해 팀이 깊이 있는 이해와 실행 가능한 기술을 갖추도록 합니다. 맞춤형 training 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**그들의 training을 차별화하는 요소:**
* 맞춤 제작 콘텐츠와 labs
* 최고 수준의 tools와 platforms 기반
* 실무자들이 설계하고 강의

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **Education** 및 **FinTech** 기관을 위한 전문 사이버보안 서비스를 제공하며, **penetration testing, cloud security assessments**, 그리고 **compliance readiness** (SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 우리 팀에는 **OSCP와 CISSP 인증 전문가**가 포함되어 있으며, 모든 프로젝트에 깊은 기술 전문성과 업계 표준 수준의 통찰을 제공합니다.

우리는 고위험 환경에 맞춘 **manual, intelligence-driven testing**으로 자동화 스캔을 넘어섭니다. 학생 기록 보호부터 금융 거래 보호까지, 우리는 조직이 가장 중요한 것을 지킬 수 있도록 돕습니다.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

최신 사이버보안 소식을 확인하고 최신 상태를 유지하려면 [**blog**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps, 그리고 개발자가 Kubernetes 클러스터를 효율적으로 관리, 모니터링, 보호할 수 있도록 합니다. AI-driven insights, 고급 security framework, 그리고 직관적인 CloudMaps GUI를 활용해 클러스터를 시각화하고, 상태를 이해하며, 자신 있게 대응하세요.

또한 K8Studio는 **all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more)와 호환됩니다.

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
