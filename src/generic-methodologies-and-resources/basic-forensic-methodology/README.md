# 기본 포렌식 방법론

{{#include ../../banners/hacktricks-training.md}}

## 이미지 생성 및 마운트

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## 악성코드 분석

이 **단계는 이미지를 확보한 후 반드시 수행해야 하는 첫 번째 단계는 아닙니다**. 하지만 파일, 파일 시스템 이미지, 메모리 이미지, pcap...가 있다면 이 악성코드 분석 기술을 독립적으로 사용할 수 있으므로 **이 작업들을 염두에 두는 것이 좋습니다**:

{{#ref}}
malware-analysis.md
{{#endref}}

## 이미지 검사

장치의 **포렌식 이미지**가 주어지면 **파티션, 파일 시스템**을 **분석하고** 잠재적으로 **흥미로운 파일**(삭제된 파일 포함)을 **복구**할 수 있습니다. 방법은 다음을 참조하세요:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

사용된 OS 및 플랫폼에 따라 다양한 흥미로운 아티팩트를 검색해야 합니다:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## 특정 파일 유형 및 소프트웨어에 대한 심층 검사

매우 **의심스러운** **파일**이 있는 경우, **파일 유형 및 이를 생성한 소프트웨어**에 따라 여러 **기술**이 유용할 수 있습니다.\
다음 페이지를 읽어 흥미로운 기술을 배워보세요:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

특히 다음 페이지를 언급하고 싶습니다:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## 메모리 덤프 검사

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap 검사

{{#ref}}
pcap-inspection/
{{#endref}}

## **안티 포렌식 기술**

안티 포렌식 기술의 사용 가능성을 염두에 두세요:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## 위협 헌팅

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
