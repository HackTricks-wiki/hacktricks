# 메모리 덤프 분석

{{#include ../../../banners/hacktricks-training.md}}

## 시작

**pcap** 내에서 **악성코드**를 **검색**하기 시작하세요. [**악성코드 분석**](../malware-analysis.md)에서 언급된 **도구**를 사용하세요.

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility는 메모리 덤프 분석을 위한 주요 오픈 소스 프레임워크입니다**. 이 Python 도구는 외부 소스 또는 VMware VM에서 덤프를 분석하여 덤프의 OS 프로파일에 따라 프로세스 및 비밀번호와 같은 데이터를 식별합니다. 플러그인으로 확장 가능하여 포렌식 조사에 매우 유용합니다.

**[여기에서 치트 시트를 찾으세요](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## 미니 덤프 크래시 보고서

덤프가 작을 경우(몇 KB 또는 몇 MB 정도) 이는 아마도 미니 덤프 크래시 보고서일 것이며 메모리 덤프가 아닙니다.

![](<../../../images/image (216).png>)

Visual Studio가 설치되어 있다면 이 파일을 열고 프로세스 이름, 아키텍처, 예외 정보 및 실행 중인 모듈과 같은 기본 정보를 바인딩할 수 있습니다:

![](<../../../images/image (217).png>)

예외를 로드하고 디컴파일된 명령어를 볼 수도 있습니다.

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

어쨌든, Visual Studio는 덤프의 깊이 있는 분석을 수행하기 위한 최상의 도구는 아닙니다.

**IDA** 또는 **Radare**를 사용하여 **심층적으로** 검사해야 합니다.

​

{{#include ../../../banners/hacktricks-training.md}}
