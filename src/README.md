# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._ 

### HackTricks를 로컬에서 실행하기
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks
# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
당신의 로컬 HackTricks 복사본은 **<5분 후에 [http://localhost:3337](http://localhost:3337)**에서 **사용 가능**합니다 (책을 빌드해야 하므로, 인내심을 가지세요).

## 기업 후원사

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)는 **HACK THE UNHACKABLE**라는 슬로건을 가진 훌륭한 사이버 보안 회사입니다. 그들은 자체 연구를 수행하고 **여러 유용한 사이버 보안 서비스**를 제공하기 위해 자체 해킹 도구를 개발합니다. 이러한 서비스에는 pentesting, Red 팀 및 교육이 포함됩니다.

그들의 **블로그**를 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)에서 확인할 수 있습니다.

**STM Cyber**는 HackTricks와 같은 사이버 보안 오픈 소스 프로젝트도 지원합니다 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com)는 **스페인**에서 가장 관련성 높은 사이버 보안 이벤트이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술 지식을 촉진하는 사명**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들이 모이는 뜨거운 만남의 장소입니다.

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
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 **워크플로우**를 쉽게 구축하고 **자동화**하세요.

지금 액세스하세요:

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

오늘 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에서 저희와 함께하고 최고의 해커들과 협력하세요!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - 필수 침투 테스트 도구 키트

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**웹 앱, 네트워크 및 클라우드에 대한 해커의 관점을 얻으세요.**

**실제 비즈니스에 영향을 미치는 중요한, 악용 가능한 취약점을 찾아보고 보고하세요.** 공격 표면을 매핑하고 권한 상승을 허용하는 보안 문제를 찾기 위해 20개 이상의 맞춤형 도구를 사용하고, 자동화된 익스플로잇을 사용하여 필수 증거를 수집하여 귀하의 노력을 설득력 있는 보고서로 전환하세요.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 **검색 엔진 결과**에 **접근하기 위한** 빠르고 쉬운 실시간 API를 제공합니다. 그들은 검색 엔진을 스크랩하고, 프록시를 처리하고, 캡차를 해결하며, 모든 풍부한 구조화된 데이터를 파싱합니다.

SerpApi의 계획 중 하나에 가입하면 Google, Bing, Baidu, Yahoo, Yandex 등 다양한 검색 엔진을 스크랩하기 위한 50개 이상의 API에 접근할 수 있습니다.\
다른 제공업체와 달리 **SerpApi는 유기적 결과만 스크랩하지 않습니다**. SerpApi 응답은 항상 모든 광고, 인라인 이미지 및 비디오, 지식 그래프 및 검색 결과에 있는 기타 요소와 기능을 포함합니다.

현재 SerpApi 고객에는 **Apple, Shopify 및 GrubHub**가 포함됩니다.\
자세한 정보는 그들의 [**블로그**](https://serpapi.com/blog/)를 확인하거나 [**플레이그라운드**](https://serpapi.com/playground)에서 예제를 시도해 보세요.\
여기에서 **무료 계정을 생성**할 수 있습니다 [**여기**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – 심층 모바일 보안 과정](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

모바일 애플리케이션과 장치를 보호하기 위해 취약성 연구, 침투 테스트 및 리버스 엔지니어링을 수행하는 데 필요한 기술과 기술을 배우세요. **온디맨드 과정**을 통해 iOS 및 Android 보안을 **마스터**하고 **인증을 받으세요**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)는 **암스테르담**에 본사를 둔 전문 사이버 보안 회사로, **전 세계의** 기업을 최신 사이버 보안 위협으로부터 **보호**하는 데 도움을 주며 **공격 보안 서비스**를 **현대적인** 접근 방식으로 제공합니다.

WebSec는 암스테르담과 와이오밍에 사무소를 둔 국제 보안 회사입니다. 그들은 **올인원 보안 서비스**를 제공하며, 이는 pentesting, **보안** 감사, 인식 교육, 피싱 캠페인, 코드 검토, 익스플로잇 개발, 보안 전문가 아웃소싱 등 모든 것을 포함합니다.

WebSec의 또 다른 멋진 점은 업계 평균과 달리 WebSec가 **자신의 기술에 매우 자신감이 있다는 것입니다.** 그들은 **최고 품질의 결과를 보장**한다고 웹사이트에 명시하고 있습니다. "**우리가 해킹할 수 없다면, 당신은 지불하지 않습니다!**" 더 많은 정보는 그들의 [**웹사이트**](https://websec.net/en/)와 [**블로그**](https://websec.net/blog/)를 확인하세요!

위의 내용 외에도 WebSec는 **HackTricks의 헌신적인 후원자**이기도 합니다.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

## 라이센스 및 면책 조항

다음에서 확인하세요:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github 통계

![HackTricks Github 통계](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
