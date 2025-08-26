# 기본 포렌식 방법론

{{#include ../../banners/hacktricks-training.md}}

## 이미지 생성 및 마운트


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

이것은 **이미지를 확보한 후 반드시 가장 먼저 수행해야 하는 단계는 아닙니다**. 하지만 파일, file-system image, memory image, pcap 등이 있다면 이 malware analysis 기술들을 독립적으로 사용할 수 있으므로 이러한 작업들을 **염두에 두는 것이 좋습니다**:


{{#ref}}
malware-analysis.md
{{#endref}}

## 이미지 검사

만약 장치의 **forensic image**가 주어진다면 사용된 **partitions, file-system**을 분석하고 잠재적으로 **흥미로운 파일들**(삭제된 파일 포함)을 **복구**하는 작업을 시작할 수 있습니다. 방법은 다음을 참조하세요:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# 기본 포렌식 방법론



## 이미지 생성 및 마운트


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

이것은 **이미지를 확보한 후 반드시 가장 먼저 수행해야 하는 단계는 아닙니다**. 하지만 파일, file-system image, memory image, pcap 등이 있다면 이 malware analysis 기술들을 독립적으로 사용할 수 있으므로 이러한 작업들을 **염두에 두는 것이 좋습니다**:


{{#ref}}
malware-analysis.md
{{#endref}}

## 이미지 검사

만약 장치의 **forensic image**가 주어진다면 사용된 **partitions, file-system**을 분석하고 잠재적으로 **흥미로운 파일들**(삭제된 파일 포함)을 **복구**하는 작업을 시작할 수 있습니다. 방법은 다음을 참조하세요:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

사용된 OS나 플랫폼에 따라 검색해야 할 다양한 흥미로운 artifacts가 있습니다:


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

## 특정 파일형식 및 소프트웨어의 심층 검사

매우 **의심스러운** **파일**이 있는 경우, 해당 파일을 생성한 **file-type 및 software**에 따라 여러 가지 유용한 **트릭**이 있을 수 있습니다.\
다음 페이지를 읽어 몇 가지 흥미로운 트릭을 확인하세요:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

특히 다음 페이지를 별도로 언급하고 싶습니다:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump Inspection


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap Inspection


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

anti-forensic techniques의 사용 가능성을 염두에 두세요:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## 특정 파일형식 및 소프트웨어의 심층 검사

매우 **의심스러운** **파일**이 있는 경우, 해당 파일을 생성한 **file-type 및 software**에 따라 여러 가지 유용한 **트릭**이 있을 수 있습니다.\
다음 페이지를 읽어 몇 가지 흥미로운 트릭을 확인하세요:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

특히 다음 페이지를 별도로 언급하고 싶습니다:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump Inspection


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap Inspection


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

anti-forensic techniques의 사용 가능성을 염두에 두세요:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
