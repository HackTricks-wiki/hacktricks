# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인 제작자_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### 로컬에서 HackTricks 실행하기
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
로컬에 있는 HackTricks 복사본은 **[http://localhost:3337](http://localhost:3337)** 에서 <5분 후 사용 가능합니다(책을 빌드해야 하므로 잠시 기다려 주세요).

## 기업 스폰서

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 슬로건이 **HACK THE UNHACKABLE**인 훌륭한 사이버보안 회사입니다. 자체 연구를 수행하고 자체 해킹 도구를 개발하여 pentesting, Red teams 및 교육과 같은 여러 가지 가치 있는 사이버보안 서비스를 **제공합니다**.

그들의 **블로그**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 또한 HackTricks 같은 사이버보안 오픈소스 프로젝트를 지원합니다 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com)은 **Spain**에서 가장 영향력 있는 사이버보안 행사이자 **Europe**에서 가장 중요한 행사 중 하나입니다. **the mission of promoting technical knowledge**라는 목표로 기술 및 사이버보안 분야의 다양한 전문가들이 모이는 핵심 만남의 장입니다.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **Europe's #1** ethical hacking 및 **bug bounty platform.**

Bug bounty 팁: 해커가 만든 해커를 위한 프리미엄 bug bounty platform인 **Intigriti**에 **가입**하세요! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 시작하여 최대 **$100,000**의 보상을 받기 시작하세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)을 사용하여 세계에서 가장 **진보된** 커뮤니티 도구로 구동되는 워크플로를 쉽게 구축하고 **자동화**하세요.

지금 이용해보세요:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하여 경험 많은 hackers 및 bug bounty hunters와 소통하세요!

- **Hacking Insights:** 해킹의 스릴과 도전 과제를 다루는 콘텐츠를 접하세요
- **Real-Time Hack News:** 실시간 뉴스와 인사이트로 빠르게 변화하는 해킹 세계의 최신 소식을 확인하세요
- **Latest Announcements:** 새로 시작되는 bug bounties와 중요한 플랫폼 업데이트를 놓치지 마세요

**지금 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에서 참여하고 최고의 hackers와 협업을 시작하세요!**

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

웹 앱, 네트워크 및 클라우드에 대해 hacker의 관점을 얻으세요.

**Find and report critical, exploitable vulnerabilities with real business impact.** 20개 이상의 맞춤 도구를 사용하여 공격 표면을 맵핑하고, 권한 상승을 유도하는 보안 문제를 찾고, 자동화된 exploits를 통해 필수 증거를 수집하여 여러분의 노력을 설득력 있는 보고서로 전환하세요.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 검색 엔진 결과에 **실시간으로 접근(access search engine results)**할 수 있는 빠르고 쉬운 API를 제공합니다. 검색 엔진을 스크랩하고, 프록시를 관리하며, 캡차를 해결하고, 모든 구조화된 리치 데이터를 파싱해 줍니다.

SerpApi의 구독은 Google, Bing, Baidu, Yahoo, Yandex 등 다양한 검색 엔진을 스크래핑하기 위한 50개 이상의 API 접근을 포함합니다.  
다른 제공자와 달리, **SerpApi는 단순히 organic results만 스크랩하지 않습니다.** SerpApi 응답에는 광고, 인라인 이미지와 동영상, 지식 그래프 등 검색 결과에 포함된 모든 요소가 일관되게 포함됩니다.

현재 SerpApi 고객에는 **Apple, Shopify, and GrubHub**가 포함됩니다.  
자세한 내용은 그들의 [**blog**](https://serpapi.com/blog/)**,** 또는 [**playground**](https://serpapi.com/playground)**에서 예제를 시도해 보세요.**  
**무료 계정 생성**은 [**여기**](https://serpapi.com/users/sign_up)**에서 가능합니다.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

모바일 애플리케이션과 기기를 보호하기 위한 vulnerability research, penetration testing, 및 reverse engineering에 필요한 기술과 역량을 배우세요. 온디맨드 과정을 통해 iOS와 Android 보안을 마스터하고 **get certified** 하세요:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **Amsterdam**에 본사를 둔 전문 사이버보안 회사로, **offensive-security services**를 모던한 접근 방식으로 제공하여 전 세계 비즈니스를 최신 사이버 위협으로부터 **protecting** 합니다.

WebSec는 Amsterdam과 Wyoming에 오피스를 둔 국제 보안 회사입니다. 이들은 Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등 **all-in-one security services**를 제공합니다.

또한 WebSec는 업계 평균과 달리 자신들의 역량에 대해 매우 자신감을 가지고 있으며, 웹사이트에 명시된 바와 같이 "**If we can't hack it, You don't pay it!**" 라는 품질 보장을 제공합니다. 자세한 내용은 그들의 [**website**](https://websec.net/en/) 및 [**blog**](https://websec.net/blog/)를 확인하세요!

또한 WebSec는 HackTricks의 헌신적인 서포터이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)는 data breach (leak) 검색 엔진입니다.  
우리는 여러 출처의 데이터에 대해 크고 작은 모든 유형의 data leaks에 걸쳐 랜덤 문자열 검색(google 유사)을 제공합니다 -- 큰 유출뿐만 아니라 작은 유출까지 모두 포함합니다.  
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration 등 pentester가 필요로 하는 모든 기능을 제공합니다.  
**HackTricks는 계속해서 우리 모두에게 훌륭한 학습 플랫폼이며, 저희는 이를 후원하게 되어 자랑스럽습니다!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**  
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 설계하고 주도하는 효과적인 사이버보안 교육을 개발하고 제공합니다. 이들의 프로그램은 이론을 넘어 실무 중심의 깊이 있는 이해와 실행 가능한 기술을 팀에 제공합니다. 실제 위협을 반영한 맞춤 환경을 사용하며, 맞춤형 교육 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**그들의 교육이 돋보이는 이유:**
* 맞춤 제작된 콘텐츠와 랩
* 최고 수준의 도구와 플랫폼으로 지원
* 실무자가 설계하고 강의

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 Education 및 FinTech 기관을 위한 전문화된 사이버보안 서비스를 제공하며, 특히 penetration testing, cloud security assessments 및 compliance readiness (SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 우리 팀에는 **OSCP and CISSP certified professionals**가 포함되어 있어 깊은 기술 전문성과 업계 표준에 기반한 인사이트를 제공합니다.

우리는 자동화 스캔을 넘어서 **manual, intelligence-driven testing**을 통해 고위험 환경에 맞춘 테스트를 제공합니다. 학생 기록 보호부터 금융 거래 보호까지, 중요한 자산을 방어하도록 돕습니다.

_“질 좋은 방어는 공격을 아는 데서 시작되며, 우리는 이해를 통해 보안을 제공합니다.”_

최신 사이버보안 소식과 업데이트는 그들의 [**blog**](https://www.lasttowersolutions.com/blog)에서 확인하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps 및 개발자가 Kubernetes 클러스터를 효율적으로 관리, 모니터링 및 보호할 수 있도록 지원합니다. AI 기반 인사이트, 고급 보안 프레임워크 및 직관적인 CloudMaps GUI를 활용하여 클러스터를 시각화하고 상태를 파악하며 자신 있게 조치할 수 있습니다.

또한 K8Studio는 주요 모든 kubernetes 배포판(AWS, GCP, Azure, DO, Rancher, K3s, Openshift 등)과 **호환**됩니다.

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## 라이선스 및 면책사항

확인하기:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github 통계

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
