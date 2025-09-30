# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

당신의 로컬 HackTricks 복사본은 <5분 후 **[http://localhost:3337](http://localhost:3337)**에서 이용할 수 있습니다(책을 빌드해야 하므로 잠시 기다려 주세요).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)은 슬로건이 **HACK THE UNHACKABLE**인 훌륭한 사이버보안 회사입니다. 자체 연구를 수행하고 자체 해킹 도구를 개발하여 pentesting, Red teams 및 교육과 같은 **여러 가치 있는 사이버보안 서비스를 제공합니다**.

그들의 **블로그**는 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다

**STM Cyber**는 또한 HackTricks와 같은 사이버보안 오픈 소스 프로젝트를 지원합니다 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com)은 **스페인**에서 가장 중요한 사이버보안 행사이자 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술 지식의 증진**이라는 사명을 가지고 이 컨퍼런스는 모든 분야의 기술 및 사이버보안 전문가들이 모이는 활발한 만남의 장입니다.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **유럽의 #1** ethical hacking 및 **bug bounty 플랫폼**입니다.

**Bug bounty tip**: **Intigriti**에 **가입**하세요 — 해커가 만들고 해커를 위해 만든 프리미엄 bug bounty 플랫폼입니다! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에 가입하여 최대 **$100,000**의 보상을 받아보세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 진보된 커뮤니티 도구로 구동되는 워크플로우를 손쉽게 구축하고 자동화하세요.

지금 이용해보세요:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** 해킹의 짜릿함과 도전 과제를 다루는 콘텐츠를 접하세요
- **Real-Time Hack News:** 빠르게 변화하는 해킹 세계의 뉴스와 인사이트를 실시간으로 확인하세요
- **Latest Announcements:** 새로 출시되는 bug bounty와 중요한 플랫폼 업데이트 정보를 받아보세요

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**웹 애플리케이션, 네트워크 및 클라우드에 대해 해커의 관점으로 진단하세요**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 검색 엔진 결과에 실시간으로 빠르고 쉽게 접근할 수 있는 API를 제공합니다. 그들은 검색 엔진을 크롤링하고, 프록시를 처리하며, 캡차를 해결하고, 모든 구조화된 풍부한 데이터를 파싱해 줍니다.

SerpApi의 구독 플랜 하나로 Google, Bing, Baidu, Yahoo, Yandex 등 다양한 검색 엔진을 스크래핑하는 50개 이상의 API에 접근할 수 있습니다.\
다른 제공자와 달리, **SerpApi는 단순히 유기적 결과만 스크래핑하지 않습니다**. SerpApi 응답에는 광고, 인라인 이미지 및 비디오, knowledge graphs 등 검색 결과에 포함된 모든 요소와 기능이 일관되게 포함됩니다.

현재 SerpApi 고객에는 **Apple, Shopify, GrubHub**가 포함됩니다.\
자세한 내용은 그들의 [**블로그**](https://serpapi.com/blog/)를 확인하거나 [**playground**](https://serpapi.com/playground)에서 예제를 실행해 보세요.\
[**여기**](https://serpapi.com/users/sign_up)에서 무료 계정을 생성할 수 있습니다.

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

모바일 애플리케이션과 기기를 보호하기 위해 취약점 연구, 침투 테스트, 리버스 엔지니어링에 필요한 기술과 역량을 배우세요. **iOS 및 Android 보안**을 온디맨드 코스로 학습하고 **인증**을 받으세요:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **암스테르담**에 본사를 둔 전문 사이버보안 회사로, **전 세계 기업들을 보호**하기 위해 현대적인 접근 방식으로 **offensive-security services**를 제공합니다.

WebSec는 암스테르담과 Wyoming에 사무소를 둔 국제 보안 회사입니다. 그들은 Pentesting, **Security** 감사, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing 등 **올인원 보안 서비스**를 제공합니다.

WebSec의 또 다른 장점은 업계 평균과 달리 스스로의 역량에 **매우 자신감**을 가지고 있으며, 그들은 **최고 품질의 결과를 보장**한다고 웹사이트에 명시하고 있습니다: "**If we can't hack it, You don't pay it!**". 자세한 내용은 그들의 [**웹사이트**](https://websec.net/en/)와 [**블로그**](https://websec.net/blog/)를 확인하세요!

또한 WebSec는 HackTricks의 적극적인 후원사입니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)는 데이터 유출 (leak) 검색 엔진입니다. \
우리는 대형이든 소형이든 모든 유형의 데이터 leak에 대해 구글과 유사한 랜덤 문자열 검색을 제공합니다 -- 대형 사례뿐만 아니라 다양한 출처의 데이터를 대상으로 합니다. \
사람 검색, AI 검색, 조직 검색, API (OpenAPI) 접근, theHarvester 통합 등 pentester가 필요로 하는 모든 기능을 제공합니다.\
**HackTricks는 계속해서 우리 모두에게 훌륭한 학습 플랫폼이며, 저희는 이를 후원하게 되어 자랑스럽습니다!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 설계하고 주도하는 효과적인 사이버보안 교육을 개발하고 제공합니다. 그들의 프로그램은 이론을 넘어 실제 위협을 반영한 맞춤형 환경을 사용하여 팀에게 깊이 있는 이해와 실전 가능한 기술을 제공합니다. 맞춤형 교육 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)를 통해 문의하세요.

**그들의 교육이 특별한 이유:**
* 맞춤형 콘텐츠 및 실습 환경
* 최고 수준의 도구 및 플랫폼 지원
* 현업 실무자가 설계하고 강의

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **교육(Education)** 및 **핀테크(FinTech)** 기관을 위한 전문화된 사이버보안 서비스를 제공하며, 특히 **penetration testing, cloud security assessments**, 및 **compliance readiness**(SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 우리 팀에는 **OSCP 및 CISSP 자격 보유 전문가**가 포함되어 있어 깊은 기술 전문성과 업계 표준 통찰을 제공합니다.

우리는 자동화된 스캔을 넘어 **수동 기반의 인텔리전스 주도 테스트**를 통해 고위험 환경에 맞춤형 테스트를 제공합니다. 학생 기록 보호에서 금융 거래 보안에 이르기까지, 중요한 자산을 방어할 수 있도록 돕습니다.

_“질 좋은 방어는 공격을 이해하는 데서 시작됩니다. 우리는 이해를 통한 보안을 제공합니다.”_

최신 사이버보안 소식을 보려면 그들의 [**블로그**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE는 DevOps, DevSecOps 및 개발자들이 Kubernetes 클러스터를 효율적으로 관리, 모니터링 및 보호할 수 있도록 지원합니다. AI 기반 인사이트, 고급 보안 프레임워크 및 직관적인 CloudMaps GUI를 활용하여 클러스터를 시각화하고 상태를 파악하며 자신 있게 조치할 수 있습니다.

또한 K8Studio는 모든 주요 kubernetes 배포판(AWS, GCP, Azure, DO, Rancher, K3s, Openshift 등)과 **호환됩니다**.

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
