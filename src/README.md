# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인:_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

## 기업 후원사

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)은 슬로건이 **HACK THE UNHACKABLE**인 훌륭한 사이버보안 회사입니다. 자체 연구를 수행하고 자체 해킹 도구를 개발하여 **pentesting, Red teams 및 교육 같은 여러 가치 있는 사이버보안 서비스를 제공합니다.**

그들의 **블로그**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 또한 HackTricks와 같은 사이버보안 오픈 소스 프로젝트를 지원합니다 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com)는 **스페인**에서 가장 중요한 사이버보안 행사이며 **유럽**에서도 손꼽히는 행사 중 하나입니다. **기술 지식 전파**를 사명으로 하는 이 컨퍼런스는 모든 분야의 기술 및 사이버보안 전문가들이 모이는 중요한 만남의 장입니다.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **유럽 최고의(#1)** 윤리적 해킹 및 **bug bounty 플랫폼**입니다.

**버그 바운티 팁**: 해커가 만든 프리미엄 버그 바운티 플랫폼인 **Intigriti**에 **가입**하세요! 지금 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 참여하여 최대 **$100,000**의 보상을 받으세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
세계에서 가장 **진보된** 커뮤니티 도구들로 구동되는 워크플로를 쉽게 구축하고 **자동화**하려면 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하세요.

지금 액세스하기:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하여 경험 많은 해커 및 버그 바운티 헌터들과 소통하세요!

- **해킹 인사이트:** 해킹의 스릴과 도전을 다루는 콘텐츠에 참여하세요
- **실시간 해킹 뉴스:** 빠르게 변하는 해킹 세계의 최신 뉴스와 인사이트를 실시간으로 받아보세요
- **최신 공지:** 새로 시작되는 버그 바운티와 중요한 플랫폼 업데이트를 확인하세요

**지금 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에 가입하여 최고의 해커들과 협업을 시작하세요!**

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 **실무 중심의 AI 보안 교육**을 엔지니어링 우선의 핸즈온 랩 방식으로 제공합니다. 우리의 과정은 보안 엔지니어, AppSec 전문가, 그리고 실제 AI/LLM 기반 애플리케이션을 **구축, 공격, 보호**하려는 개발자를 위해 설계되었습니다.

**AI Security Certification**은 다음과 같은 실무 기술에 중점을 둡니다:
- LLM 및 AI 기반 애플리케이션의 보안
- AI 시스템에 대한 위협 모델링
- Embeddings, vector databases, 및 RAG 보안
- LLM 공격, 남용 시나리오 및 실질적인 방어책
- 안전한 설계 패턴 및 배포 고려사항

모든 과정은 **온디맨드**, **랩 중심**이며 단지 이론이 아닌 **현실 세계의 보안 트레이드오프**에 맞춰 설계되어 있습니다.

👉 AI Security 과정에 대한 자세한 내용:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 검색 엔진 결과에 **실시간으로 접근**할 수 있는 빠르고 쉬운 API를 제공합니다. 그들은 검색 엔진을 스크래핑하고, 프록시를 관리하며, captchas를 해결하고, 모든 풍부한 구조화된 데이터를 파싱해줍니다.

SerpApi의 구독 플랜에는 Google, Bing, Baidu, Yahoo, Yandex 등 다양한 검색 엔진을 스크래핑하기 위한 50개 이상의 API 접근이 포함됩니다.\
다른 제공업체와 달리, **SerpApi는 단순히 유기적 결과만 스크래핑하지 않습니다.** SerpApi 응답에는 일관되게 광고, 인라인 이미지 및 비디오, 지식 그래프 및 검색 결과에 표시되는 기타 요소들이 포함됩니다.

현재 SerpApi 고객으로는 **Apple, Shopify, GrubHub** 등이 있습니다.\
자세한 내용은 그들의 [**블로그**](https://serpapi.com/blog/)를 확인하거나 [**playground**](https://serpapi.com/playground)에서 예제를 시도해보세요.\
[**여기**](https://serpapi.com/users/sign_up)에서 **무료 계정 생성**이 가능합니다.

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

모바일 애플리케이션 및 장치를 보호하기 위해 취약점 연구, 침투 테스트, 리버스 엔지니어링에 필요한 기술과 지식을 배우세요. **iOS 및 Android 보안**을 온디맨드 과정으로 마스터하고 **인증**을 받으세요:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **암스테르담**에 기반을 둔 전문 사이버보안 회사로, **최신 사이버보안 위협**으로부터 전 세계 기업들을 보호하기 위해 **공격적 보안 서비스(offensive-security services)**를 현대적인 접근 방식으로 제공합니다.

WebSec는 암스테르담과 Wyoming에 사무소를 둔 국제 보안 회사입니다. 그들은 Pentesting, **Security** 감사, 인식 교육, 피싱 캠페인, 코드 리뷰, 익스플로잇 개발, 보안 전문가 아웃소싱 등 **올인원 보안 서비스**를 제공합니다.

업계 평균과 달리 WebSec의 또 다른 장점은 **자신들의 역량에 매우 자신감**이 있다는 점이며, 그들은 **최고 품질의 결과를 보장**합니다. 웹사이트에는 "**If we can't hack it, You don't pay it!**"라고 명시되어 있습니다. 자세한 정보는 그들의 [**웹사이트**](https://websec.net/en/) 및 [**블로그**](https://websec.net/blog/)를 확인하세요!

또한 WebSec는 HackTricks의 **헌신적인 후원자**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**현장 중심으로 설계, 당신 중심으로 구성.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 직접 구성하고 이끄는 실용적인 사이버보안 교육을 개발하고 제공합니다. 그들의 프로그램은 이론을 넘어 실제 위협을 반영한 맞춤형 환경을 사용하여 팀에게 깊은 이해와 실무 가능한 기술을 제공하도록 설계되었습니다. 맞춤형 교육 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)에서 연락하세요.

**그들의 교육이 특별한 이유:**
* 맞춤형 콘텐츠 및 랩
* 최상급 도구와 플랫폼 지원
* 실무자가 설계하고 강의

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **교육 기관** 및 **FinTech** 기관을 위한 전문화된 사이버보안 서비스를 제공하며, 특히 **penetration testing, cloud security assessments**, 및 **compliance readiness** (SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 저희 팀에는 **OSCP 및 CISSP 인증 전문가들**이 포함되어 있어 모든 참여에 깊은 기술적 전문성과 업계 표준 인사이트를 제공합니다.

우리는 자동화된 스캔을 넘어 **수작업, 인텔리전스 기반의 테스트**를 통해 고위험 환경에 맞춘 서비스를 제공합니다. 학생 기록 보호에서 금융 거래 보호에 이르기까지, 조직이 가장 중요한 것을 방어하도록 돕습니다.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

최신 사이버보안 소식을 확인하려면 그들의 [**블로그**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps 및 개발자들이 Kubernetes 클러스터를 효율적으로 관리, 모니터링 및 보호할 수 있도록 지원합니다. AI 기반 인사이트, 고급 보안 프레임워크 및 직관적인 CloudMaps GUI를 활용하여 클러스터를 시각화하고 상태를 파악하며 자신 있게 조치할 수 있습니다.

또한 K8Studio는 모든 주요 Kubernetes 배포판(AWS, GCP, Azure, DO, Rancher, K3s, Openshift 등)과 **호환**됩니다.

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## 라이선스 및 면책 조항

다음에서 확인하세요:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github 통계

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
