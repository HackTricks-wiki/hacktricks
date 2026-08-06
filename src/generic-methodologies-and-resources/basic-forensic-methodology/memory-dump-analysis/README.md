# 메모리 덤프 분석

{{#include ../../../banners/hacktricks-training.md}}

## 시작

pcap 내부에서 **malware**를 **검색**하는 것부터 시작하세요. [**Malware Analysis**](../malware-analysis.md)에 언급된 **도구**를 사용하세요.

## [Volatility](volatility-cheatsheet.md)

**Volatility는 메모리 덤프 분석을 위한 주요 오픈 소스 framework입니다**. 이 Python 도구는 외부 소스 또는 VMware VM에서 생성된 덤프를 분석하며, 덤프의 OS profile을 기반으로 process와 password 같은 데이터를 식별합니다. plugin을 사용해 확장할 수 있으므로 forensic investigation에 매우 유연하게 사용할 수 있습니다.

[**여기에서 cheatsheet를 확인하세요**](volatility-cheatsheet.md)

## Mini dump crash report

덤프가 작다면(단지 몇 KB 또는 몇 MB 정도) memory dump가 아니라 mini dump crash report일 가능성이 높습니다.

![Volatility - Mini dump crash report: 덤프가 작다면(단지 몇 KB 또는 몇 MB 정도) memory dump가 아니라 mini dump crash report일 가능성이 높습니다](<../../../images/image (532).png>)

Visual Studio가 설치되어 있다면 이 파일을 열어 process name, architecture, exception info 및 실행 중인 module과 같은 기본 정보를 확인할 수 있습니다.

![Volatility - Mini dump crash report: Visual Studio가 설치되어 있다면 이 파일을 열어 process name, architecture, exception info 및...](<../../../images/image (263).png>)

exception을 load하고 decompiled instruction을 확인할 수도 있습니다.

![Volatility - Mini dump crash report: exception을 load하고 decompiled instruction을 확인할 수도 있습니다](<../../../images/image (142).png>)

![Volatility - Mini dump crash report: exception을 load하고 decompiled instruction을 확인할 수도 있습니다](<../../../images/image (610).png>)

어쨌든 Visual Studio는 dump를 심층적으로 분석하기에 가장 좋은 도구는 아닙니다.

**IDA** 또는 **Radare**를 사용해 파일을 **열고** **심층적으로** 검사해야 합니다.

{{#include ../../../banners/hacktricks-training.md}}
