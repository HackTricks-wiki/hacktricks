# 기본 포렌식 방법론

{{#include ../../banners/hacktricks-training.md}}

## 이미지 생성 및 마운트


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware 분석

이미지를 확보한 후 반드시 **처음으로 수행해야 하는 단계는 아닙니다**. 하지만 파일, 파일 시스템 이미지, 메모리 이미지, pcap 등이 있다면 이러한 malware 분석 기법을 독립적으로 사용할 수 있으므로, 다음 작업을 **염두에 두는 것이 좋습니다**:


{{#ref}}
malware-analysis.md
{{#endref}}

## 이미지 검사

장치의 **포렌식 이미지**를 제공받았다면, 사용된 **파티션과 파일 시스템을 분석**하고 잠재적으로 **흥미로운 파일을 복구**하는 작업(삭제된 파일도 포함)을 시작할 수 있습니다. 방법은 다음을 참고하세요:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

사용된 OS와 플랫폼에 따라 조사해야 할 흥미로운 아티팩트가 달라질 수 있습니다:


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

잠긴 Android 장치, 획득 경로 및 메모리 이미징에 대해서는 [Android 포렌식](android-forensics.md)을 참고하세요.

## 특정 파일 형식 및 소프트웨어 심층 검사

매우 **의심스러운** **파일**이 있다면, 파일 형식과 파일을 생성한 소프트웨어에 따라 유용한 **기법**이 있을 수 있습니다.\
흥미로운 기법을 알아보려면 다음 페이지를 읽어 보세요:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

특별히 언급하고 싶은 페이지는 다음과 같습니다:


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

## 위협 헌팅


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
