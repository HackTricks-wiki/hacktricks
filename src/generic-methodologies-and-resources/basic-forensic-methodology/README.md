# 기본 포렌식 방법론

{{#include ../../banners/hacktricks-training.md}}

## 이미지 생성 및 마운트


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

이미지를 확보한 후 수행해야 하는 **첫 번째 단계일 필요는 없습니다**. 하지만 파일, 파일 시스템 이미지, 메모리 이미지, pcap 등이 있다면 이러한 Malware Analysis 기법을 독립적으로 사용할 수 있으므로, 다음 작업을 **염두에 두는 것이 좋습니다**:


{{#ref}}
malware-analysis.md
{{#endref}}

## 이미지 검사

장치의 **포렌식 이미지**를 제공받았다면 **파티션과 파일 시스템**을 **분석**하고, 잠재적으로 **흥미로운 파일**(삭제된 파일도 포함)을 **복구**할 수 있습니다. 방법은 다음에서 알아보세요:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

사용된 OS와 플랫폼에 따라 검색해야 할 다양한 흥미로운 아티팩트가 있습니다:


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

## 특정 파일 형식 및 Software 심층 검사

매우 **의심스러운** **파일**이 있다면, 해당 파일을 생성한 **파일 형식과 Software**에 따라 몇 가지 **트릭**이 유용할 수 있습니다.\
다음 페이지를 읽고 몇 가지 흥미로운 트릭을 알아보세요:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

다음 페이지를 특별히 언급하고 싶습니다:


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

## **안티 포렌식 기법**

안티 포렌식 기법이 사용되었을 가능성을 염두에 두세요:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
