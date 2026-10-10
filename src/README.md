# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 로고 및 모션 디자인: _[_@ppieranacho_](https://www.instagram.com/ppieranacho/)_

### 로컬에서 HackTricks 실행

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

HackTricks의 로컬 사본은 5분 이내에 [http://localhost:3337](http://localhost:3337)에서 **사용할 수 있습니다**(책을 빌드해야 하니 잠시 기다려 주세요).

또는 Docker Compose가 있다면 저장소 루트에서 다음 명령을 실행하면 됩니다:

```bash
docker compose up
```

이는 번들로 제공되는 `docker-compose.yml`을 사용해 호스트에서 현재 체크아웃된 브랜치를 live reload와 함께 [http://localhost:3337](http://localhost:3337)에서 제공합니다. Compose를 사용할 때 언어를 변경하려면 서비스를 시작하기 전에 원하는 언어 브랜치를 체크아웃하세요.

## HackTricks 파트너

---

## HackTricks 후원사

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber는 penetration testing, 보안 감사, exploit 및 연구 작업, 도구, 보안 인식 교육 서비스를 제공합니다. 웹사이트에 따르면 침투 테스터, 프로그래머, 보안 연구원으로 구성된 팀이 10년 넘는 경험을 보유하고 있습니다.<sup>[[1]](#references)</sup>

[**블로그**](https://blog.stmcyber.com)에서 더 자세히 확인할 수 있습니다.

**STM Cyber**는 HackTricks와 같은 사이버 보안 오픈소스 프로젝트도 지원합니다 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti는 전 세계 연구원 커뮤니티를 통해 bug bounty 및 penetration-testing 서비스를 제공하는 크라우드소싱 보안 업체입니다. 이 플랫폼은 지속적인 bug bounty 범위와 온디맨드 PTaaS, 관리형 취약점 공개 프로그램을 결합합니다.<sup>[[2]](#references)</sup>

**Bug bounty 팁**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)를 통해 Intigriti에 가입하고 bug bounty 프로그램을 살펴보세요.

---

### [Modern Security – AI 및 애플리케이션 보안 교육 플랫폼](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security는 보안 엔지니어, AppSec 전문가, 개발자를 위한 자기 주도형 실습 AI 보안 교육을 제공합니다. AI Security Certification 과정은 LLM 및 agent 기본, RAG 및 벡터 데이터베이스, 위협 모델링, prompt-injection 및 MCP 공격, 방어 아키텍처를 다룹니다.<sup>[[3]](#references)</sup>

👉 AI Security 과정에 대한 자세한 내용:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**는 Google 및 기타 검색 엔진용 API를 제공하며, 위치 기반 결과, Maps, Shopping, Knowledge Graph 결과 등의 기능을 갖춘 구조화된 SERP 데이터를 반환합니다.<sup>[[4]](#references)</sup>

자세한 정보는 [**블로그**](https://serpapi.com/blog/)를 확인하거나 [**플레이그라운드**](https://serpapi.com/playground)에서 예제를 실행해 보거나 [**무료 계정을 만드세요**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – 심층 모바일 및 AI 보안 과정](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy**는 자기 주도형 모바일 및 AI 보안 과정을 제공합니다. 교육 과정은 Ghidra, Frida, LLDB 같은 도구를 사용한 모바일 애플리케이션 감사 및 리버싱과 AI/LLM 공격 및 방어 실습을 다룹니다.<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy 과정 카탈로그](https://academy.8ksec.io/)를 살펴보세요.

---

### [NaxusAI – AI 기반 보안 스캐너](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus**는 코드와 인프라를 매핑한 다음 정적 및 동적 agent를 사용해 악용 가능한 취약점을 찾고 검증하며, 개념 증명 증거와 해결 지침을 제공하는 offensive-AI 플랫폼을 홍보합니다.<sup>[[7]](#references)</sup>

**코드 보안 팁**: 코드 및 인프라 중심의 취약점 탐색을 위해 Naxus를 살펴보세요.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec은 penetration testing, 보안 구독, 인력 배치, 취약점 평가 서비스를 제공합니다. 웹사이트에 따르면 국제적으로 사업을 운영하며 offensive security, defensive security, 거버넌스·위험·컴플라이언스 업무를 다룹니다.<sup>[[8]](#references)</sup>

자세한 내용은 [**웹사이트**](https://websec.net/en/) 또는 [**블로그**](https://websec.net/blog/)를 방문하세요.

위의 서비스 외에도 WebSec은 HackTricks를 **지속적으로 후원하고 있습니다.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**현장에 맞춰 만들고, 여러분을 위해 설계했습니다.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks)는 실제 인프라를 기반으로 제작한 콘텐츠와 실습 환경을 통해 전문가 주도의 사이버 보안 교육을 제공합니다. 조직의 요구에 맞춘 프로그램은 평가부터 구현까지 아우릅니다.<sup>[[9]](#references)</sup> 맞춤형 교육 문의는 [**여기**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)로 연락하세요.

**교육의 차별점:**
* 맞춤 제작 콘텐츠와 실습 환경
* 최고 수준의 도구와 플랫폼을 기반으로 제공
* 현업 전문가가 설계하고 교육

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions는 **교육** 및 **FinTech** 분야의 사이버 보안 컨설팅에 주력하며, 클라우드 평가, 내부 및 외부 penetration test, 취약점 평가, 컴플라이언스 지원을 제공합니다.<sup>[[10]](#references)</sup>

[**블로그**](https://www.lasttowersolutions.com/blog)를 방문해 최신 사이버 보안 정보를 확인하세요.

---

### [K8Studio - Kubernetes 관리를 위한 더 스마트한 GUI.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio는 CloudMaps 시각화, 멀티 클러스터 탐색, RBAC, Helm, 로그, YAML, 터미널 뷰를 갖춘 데스크톱 Kubernetes IDE입니다. 업체에 따르면 agent를 설치하지 않고 kubeconfig를 통해 연결하며 macOS, Windows, Linux 및 air-gapped 클러스터를 지원합니다.<sup>[[11]](#references)</sup>

---

## 라이선스 및 면책 조항

아래 References의 HackTricks Values & FAQ 항목을 참조하세요.

## Github 통계

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [실용적인 AI 보안: 공격, 방어 및 응용](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks 추천 링크](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec 후원 영상](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets 과정](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks 가치 및 FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
