# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인 제작:_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks will be **[http://localhost:3337](http://localhost:3337)에서 이용할 수 있습니다** after <5 minutes (it needs to build the book, be patient).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)은 슬로건이 **HACK THE UNHACKABLE**인 훌륭한 사이버보안 회사입니다. 자체 연구를 수행하고 자체 해킹 도구를 개발하여 pentesting, Red teams 및 training 같은 여러 가치 있는 사이버보안 서비스를 제공합니다.

그들의 **블로그**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 HackTricks와 같은 사이버보안 오픈 소스 프로젝트도 지원합니다 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com)는 **Spain**에서 가장 중요한 사이버보안 행사이며 **Europe**에서도 손꼽히는 주요 컨퍼런스 중 하나입니다. **기술 지식 전파**라는 사명을 가지고 있는 이 컨그레스는 모든 분야의 기술 및 사이버보안 전문가들이 모이는 중요한 만남의 장입니다.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **Europe's #1** ethical hacking 및 **bug bounty platform**입니다.

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하면 세계에서 가장 **진보된** 커뮤니티 도구로 구동되는 워크플로우를 손쉽게 구축하고 **자동화**할 수 있습니다.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** 해킹의 흥분과 도전 과제를 다루는 콘텐츠를 접할 수 있습니다
- **Real-Time Hack News:** 실시간 뉴스와 인사이트를 통해 빠르게 변화하는 해킹 세계를 따라가세요
- **Latest Announcements:** 새로 시작되는 bug bounty와 중요한 플랫폼 업데이트를 확인하세요

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**웹 애플리케이션, 네트워크 및 클라우드에 대해 해커의 관점으로 평가하세요**

**비즈니스에 실질적인 영향을 주는 치명적인 취약점을 찾아 보고하세요.** 20개 이상의 맞춤 도구를 사용해 공격 표면을 매핑하고, 권한 상승을 허용하는 보안 문제를 찾아내며, 자동화된 익스플로잇으로 핵심 증거를 수집해 수고를 설득력 있는 보고서로 전환하세요.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 검색 엔진 결과에 접근할 수 있는 빠르고 쉬운 실시간 APIs를 제공합니다. 이들은 검색 엔진을 스크레이핑하고, 프록시를 처리하며, 캡차를 해결하고, 모든 구조화된 데이터를 파싱해 줍니다.

SerpApi의 플랜 구독은 Google, Bing, Baidu, Yahoo, Yandex 등을 포함한 50개 이상의 서로 다른 검색 엔진용 API 접근을 포함합니다.\
다른 제공업체와 달리, **SerpApi는 단순히 유기적 결과만 스크랩하지 않습니다**. SerpApi 응답은 광고, 인라인 이미지 및 비디오, 지식 그래프 등 검색 결과에 포함된 모든 요소를 일관되게 포함합니다.

현재 SerpApi 고객으로는 **Apple, Shopify, and GrubHub**가 있습니다.\
자세한 내용은 그들의 [**blog**](https://serpapi.com/blog/)**을** 확인하거나 [**playground**](https://serpapi.com/playground)**에서 예제를 시도해 보세요.**\
무료 계정을 [**here**](https://serpapi.com/users/sign_up)**에서 생성할 수 있습니다.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

모바일 애플리케이션과 기기를 보호하기 위해 취약점 리서치, penetration testing 및 reverse engineering을 수행하는 데 필요한 기술과 역량을 배우세요. 온디맨드 코스를 통해 iOS 및 Android 보안을 마스터하고 **인증**을 획득하세요:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **Amsterdam**에 기반을 둔 전문 사이버보안 회사로, **전 세계** 기업들을 최신 사이버보안 위협으로부터 보호하는 데 도움을 주며 **offensive-security services**를 **현대적인** 접근 방식으로 제공합니다.

WebSec는 Amsterdam과 Wyoming에 오피스를 둔 국제적인 보안 회사입니다. 그들은 Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등 **올인원 보안 서비스**를 제공합니다.

WebSec의 또 다른 장점은 업계 평균과 달리 WebSec가 자신의 실력에 대해 **매우 자신감**이 있다는 점으로, 그들은 **최고 품질의 결과를 보장**합니다. 그들의 웹사이트에는 "**If we can't hack it, You don't pay it!**"라고 명시되어 있습니다. 자세한 정보는 그들의 [**website**](https://websec.net/en/) 및 [**blog**](https://websec.net/blog/)를 확인하세요!

또한 WebSec는 HackTricks의 **헌신적인 후원자**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 설계하고 주도하는 효과적인 사이버보안 교육을 개발하고 제공합니다. 이들의 프로그램은 이론을 넘어서 실전 위협을 반영한 맞춤형 환경을 사용하여 팀에 깊은 이해와 실무 가능한 기술을 제공합니다. 맞춤형 교육 문의는 [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)에서 문의하세요.

**그들의 교육이 돋보이는 이유:**
* 맞춤 제작된 콘텐츠와 실습실
* 최고 수준의 도구와 플랫폼 지원
* 실무자가 설계하고 강의

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 교육 및 FinTech 기관을 위한 전문화된 사이버보안 서비스를 제공하며, 특히 penetration testing, cloud security assessments 및 **compliance readiness**(SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 저희 팀은 OSCP 및 CISSP 인증 전문가를 포함해 모든 계약에 깊은 기술적 전문성과 업계 표준 통찰을 제공합니다.

자동화 스캔을 넘어 **수작업, 인텔리전스 기반 테스트**를 제공하며 고위험 환경에 맞춘 맞춤형 검사를 수행합니다. 학생 기록 보호부터 금융 거래 보호까지, 조직이 가장 중요한 자산을 지킬 수 있도록 돕습니다.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

최신 사이버보안 소식을 보려면 그들의 [**blog**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps 및 개발자가 Kubernetes 클러스터를 효율적으로 관리, 모니터링 및 보호할 수 있게 해줍니다. AI 기반 인사이트, 고급 보안 프레임워크 및 직관적인 CloudMaps GUI를 활용해 클러스터를 시각화하고 상태를 파악하며 자신 있게 조치할 수 있습니다.

게다가 K8Studio는 **모든 주요 kubernetes distributions**(AWS, GCP, Azure, DO, Rancher, K3s, Openshift 등)과 호환됩니다.

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
