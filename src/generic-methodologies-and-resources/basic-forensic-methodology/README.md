# 기본 Forensic Methodology

{{#include ../../banners/hacktricks-training.md}}

## Image 생성 및 마운트


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

**image를 확보한 후 수행해야 하는 첫 번째 단계는 아닐 수 있습니다**. 하지만 파일, file-system image, memory image, pcap 등이 있다면 이러한 malware analysis techniques를 독립적으로 사용할 수 있으므로, 다음 **작업을 염두에 두는 것이 좋습니다**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Image 검사

장치의 **forensic image**가 제공된 경우 **partition과 사용된 file-system을 분석**하고 잠재적으로 **흥미로운 파일**(삭제된 파일도 포함)을 **복구**할 수 있습니다. 방법은 다음에서 확인할 수 있습니다:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

사용된 OS와 platform에 따라 검색해야 할 흥미로운 artifact가 달라집니다:


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

## 특정 file-type 및 Software 심층 검사

매우 **의심스러운** **파일**이 있다면, 해당 파일을 생성한 **file-type과 software에 따라** 여러 **trick**이 유용할 수 있습니다.\
다음 페이지를 읽고 몇 가지 흥미로운 trick을 알아보세요:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

다음 페이지를 특별히 언급하고 싶습니다:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump 검사


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap 검사


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

anti-forensic techniques가 사용되었을 가능성을 염두에 두세요:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
