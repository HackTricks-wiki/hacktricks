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
당신의 로컬 HackTricks 복사본은 **<5분 후에 [http://localhost:3337](http://localhost:3337)** **사용 가능할 것입니다 (책을 빌드해야 하므로, 인내심을 가지세요).**

## 기업 후원사

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 **HACK THE UNHACKABLE**라는 슬로건을 가진 훌륭한 사이버 보안 회사입니다. 그들은 자체 연구를 수행하고 **여러 가치 있는 사이버 보안 서비스**를 제공하기 위해 자체 해킹 도구를 개발합니다. 이러한 서비스에는 pentesting, Red 팀 및 교육이 포함됩니다.

그들의 **블로그**를 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 HackTricks와 같은 사이버 보안 오픈 소스 프로젝트도 지원합니다 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com)는 **스페인**에서 가장 관련성이 높은 사이버 보안 이벤트이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술 지식을 촉진하는 사명**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들이 모이는 뜨거운 만남의 장소입니다.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**는 **유럽의 #1** 윤리적 해킹 및 **버그 바운티 플랫폼**입니다.

**버그 바운티 팁**: **Intigriti**에 **가입**하세요. 해커를 위해 해커가 만든 프리미엄 **버그 바운티 플랫폼**입니다! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에 가입하고 최대 **$100,000**의 보상을 받기 시작하세요!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 **자동화**하세요.

오늘 액세스하세요:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

경험이 풍부한 해커 및 버그 바운티 헌터와 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하세요!

- **해킹 통찰력:** 해킹의 스릴과 도전에 대한 내용을 다루는 콘텐츠에 참여하세요.
- **실시간 해킹 뉴스:** 실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.
- **최신 발표:** 새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대한 정보를 유지하세요.

오늘 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에 가입하고 최고의 해커들과 협력하세요!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - 필수 침투 테스트 도구 키트

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**웹 앱, 네트워크 및 클라우드에 대한 해커의 관점을 얻으세요.**

**실제 비즈니스에 영향을 미치는 중요한, 악용 가능한 취약점을 찾아보고 보고하세요.** 공격 표면을 매핑하고 권한 상승을 허용하는 보안 문제를 찾고, 필수 증거를 수집하기 위해 자동화된 익스플로잇을 사용하여 귀하의 노력을 설득력 있는 보고서로 전환하세요.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 **검색 엔진 결과**에 **빠르고 쉽게** 접근할 수 있는 실시간 API를 제공합니다. 그들은 검색 엔진을 스크랩하고, 프록시를 처리하고, 캡차를 해결하며, 모든 풍부한 구조화된 데이터를 파싱합니다.

SerpApi의 플랜 중 하나에 가입하면 Google, Bing, Baidu, Yahoo, Yandex 등 다양한 검색 엔진을 스크랩하기 위한 50개 이상의 API에 접근할 수 있습니다.\
다른 제공업체와 달리 **SerpApi는 유기적 결과만 스크랩하지 않습니다**. SerpApi 응답은 항상 모든 광고, 인라인 이미지 및 비디오, 지식 그래프 및 검색 결과에 있는 기타 요소와 기능을 포함합니다.

현재 SerpApi 고객에는 **Apple, Shopify, GrubHub**가 포함됩니다.\
자세한 정보는 그들의 [**블로그**](https://serpapi.com/blog/)를 확인하거나 [**플레이그라운드**](https://serpapi.com/playground)에서 예제를 시도해 보세요.\
여기에서 **무료 계정**을 [**생성**](https://serpapi.com/users/sign_up)할 수 있습니다.**

---

### [8kSec Academy – 심층 모바일 보안 과정](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

취약점 연구, 침투 테스트 및 리버스 엔지니어링을 수행하여 모바일 애플리케이션과 장치를 보호하는 데 필요한 기술과 기술을 배우세요. **온디맨드 과정**을 통해 iOS 및 Android 보안을 **마스터**하고 **인증을 받으세요**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **암스테르담**에 본사를 둔 전문 사이버 보안 회사로, **전 세계**의 기업을 최신 사이버 보안 위협으로부터 **보호**하기 위해 **공격 보안 서비스**를 제공합니다.

WebSec는 암스테르담과 와이오밍에 사무소를 둔 국제 보안 회사입니다. 그들은 **올인원 보안 서비스**를 제공하며, 이는 모든 것을 포함합니다; Pentesting, **보안** 감사, 인식 교육, 피싱 캠페인, 코드 검토, 익스플로잇 개발, 보안 전문가 아웃소싱 등입니다.

WebSec의 또 다른 멋진 점은 업계 평균과 달리 WebSec가 **자신의 기술에 매우 자신감이 있다는 것입니다.** 그들은 **최고 품질의 결과를 보장**한다고 웹사이트에 명시하고 있습니다. "**우리가 해킹할 수 없다면, 당신은 지불하지 않습니다!**" 더 많은 정보는 그들의 [**웹사이트**](https://websec.net/en/)와 [**블로그**](https://websec.net/blog/)를 확인하세요!

위의 내용 외에도 WebSec는 **HackTricks의 헌신적인 후원자**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)는 데이터 유출 검색 엔진입니다. \
우리는 모든 유형의 데이터 유출에 대해 무작위 문자열 검색(구글과 유사)을 제공합니다. \
사람 검색, AI 검색, 조직 검색, API (OpenAPI) 접근, theHarvester 통합 등, 모든 기능이 pentester에게 필요합니다.\
**HackTricks는 우리 모두에게 훌륭한 학습 플랫폼으로 계속되고 있으며, 우리는 이를 후원하게 되어 자랑스럽습니다!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>

**현장을 위해 만들어졌습니다. 당신을 중심으로 만들어졌습니다.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 업계 전문가들이 구축하고 이끄는 효과적인 사이버 보안 교육을 개발하고 제공합니다. 그들의 프로그램은 이론을 넘어 팀에 깊은 이해와 실행 가능한 기술을 제공하며, 실제 위협을 반영하는 맞춤형 환경을 사용합니다. 맞춤형 교육 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)에서 문의하세요.

**그들의 교육을 차별화하는 요소:**
* 맞춤형 콘텐츠 및 실습실
* 최고급 도구 및 플랫폼 지원
* 실무자에 의해 설계되고 교육됨

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **교육** 및 **핀테크** 기관을 위한 전문 사이버 보안 서비스를 제공하며, **침투 테스트, 클라우드 보안 평가** 및 **준수 준비**(SOC 2, PCI-DSS, NIST)에 중점을 둡니다. 우리 팀은 **OSCP 및 CISSP 인증 전문가**로 구성되어 있으며, 모든 참여에 깊은 기술 전문성과 업계 표준 통찰력을 제공합니다.

우리는 **수동적이고 정보 기반의 테스트**를 통해 자동화된 스캔을 넘어 고위험 환경에 맞춤화된 서비스를 제공합니다. 학생 기록을 보호하는 것부터 금융 거래를 보호하는 것까지, 우리는 조직이 가장 중요한 것을 방어하도록 돕습니다.

_“양질의 방어는 공격을 아는 것을 요구합니다. 우리는 이해를 통해 보안을 제공합니다.”_

최신 사이버 보안 정보를 얻으려면 우리의 [**블로그**](https://www.lasttowersolutions.com/blog)를 방문하세요.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

## 라이센스 및 면책 조항

다음에서 확인하세요:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github 통계

![HackTricks Github 통계](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
