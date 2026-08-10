# 메모리 dump 분석

## 시작

pcap 내부에서 **malware**를 **검색**하는 것부터 시작하세요. [**Malware Analysis**](../malware-analysis.md)에 언급된 **tools**를 사용하세요.

## [Volatility](volatility-cheatsheet.md)

**Volatility는 메모리 dump 분석을 위한 오픈 소스 프레임워크입니다**. 이 Python 도구는 외부 소스 또는 VMware VM에서 생성된 dump를 분석하며, dump의 OS 프로필을 기반으로 프로세스와 비밀번호 같은 데이터를 식별합니다. 플러그인을 사용해 확장할 수 있으므로 forensic 조사에 매우 다양하게 활용할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

[**여기에서 cheatsheet를 확인하세요**](volatility-cheatsheet.md)

## Mini dump crash report

dump가 작은 경우(일부 KB 또는 몇 MB 정도) 전체 메모리 dump가 아니라 mini dump crash report일 수 있습니다.<sup>[[3]](#references)</sup>

![Volatility - Mini dump crash report: Mini DuMP crash report로 식별된 작은 dump 파일](<../../../images/image (532).png>)

Visual Studio가 설치되어 있다면 이 파일을 열어 프로세스 이름, 아키텍처, exception 세부 정보 및 로드된 모듈과 같은 기본 정보를 확인할 수 있습니다.<sup>[[4]](#references)</sup>

![Volatility - Mini dump crash report: Visual Studio가 설치되어 있다면 이 파일을 열어 프로세스 이름, 아키텍처, exception 정보 등의 기본 정보를 확인할 수 있습니다...](<../../../images/image (263).png>)

또한 exception을 검사하고 모듈의 disassembly를 확인할 수 있습니다.<sup>[[4]](#references)</sup>

![Visual Studio minidump Actions 패널의 네이티브 디버깅 및 symbol path 설정 옵션](<../../../images/image (142).png>)

![minidump exception의 instruction에 대한 Visual Studio disassembly](<../../../images/image (610).png>)

어쨌든 Visual Studio는 dump를 심층적으로 분석하기에 가장 좋은 도구는 아닙니다.

**IDA** 또는 **Radare**를 사용해 이를 **열고**, **심층적으로** 검사해야 합니다.

## References

- [1] [Volatility 프레임워크](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility 사용법](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump 파일](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Visual Studio 디버거에서 dump 파일 사용](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
