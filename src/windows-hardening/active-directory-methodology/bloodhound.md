# BloodHound & Other AD Enum Tools

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)는 Sysinternal Suite의 도구입니다:

> 고급 Active Directory (AD) 뷰어 및 편집기입니다. AD Explorer를 사용하여 AD 데이터베이스를 쉽게 탐색하고, 즐겨찾기 위치를 정의하고, 대화 상자를 열지 않고도 객체 속성과 특성을 보고, 권한을 편집하고, 객체의 스키마를 보고, 저장하고 다시 실행할 수 있는 정교한 검색을 수행할 수 있습니다.

### Snapshots

AD Explorer는 AD의 스냅샷을 생성할 수 있어 오프라인에서 확인할 수 있습니다.\
오프라인에서 취약점을 발견하거나 시간에 따라 AD DB의 다양한 상태를 비교하는 데 사용할 수 있습니다.

연결하려면 사용자 이름, 비밀번호 및 방향이 필요합니다 (모든 AD 사용자가 필요합니다).

AD의 스냅샷을 찍으려면 `File` --> `Create Snapshot`으로 이동하고 스냅샷의 이름을 입력합니다.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon)은 AD 환경에서 다양한 아티팩트를 추출하고 결합하는 도구입니다. 이 정보는 분석을 용이하게 하고 대상 AD 환경의 현재 상태에 대한 전체적인 그림을 제공하는 메트릭이 포함된 **특별히 형식화된** Microsoft Excel **보고서**로 제공될 수 있습니다.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound는 [Linkurious](http://linkurio.us/) 위에 구축된 단일 페이지 Javascript 웹 애플리케이션으로, [Electron](http://electron.atom.io/)으로 컴파일되었으며, C# 데이터 수집기로 공급되는 [Neo4j](https://neo4j.com/) 데이터베이스를 사용합니다.

BloodHound는 그래프 이론을 사용하여 Active Directory 또는 Azure 환경 내의 숨겨진 관계와 종종 의도하지 않은 관계를 드러냅니다. 공격자는 BloodHound를 사용하여 빠르게 식별할 수 없는 복잡한 공격 경로를 쉽게 식별할 수 있습니다. 방어자는 BloodHound를 사용하여 동일한 공격 경로를 식별하고 제거할 수 있습니다. 블루 팀과 레드 팀 모두 BloodHound를 사용하여 Active Directory 또는 Azure 환경에서 권한 관계에 대한 더 깊은 이해를 쉽게 얻을 수 있습니다.

그래서, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound)는 도메인을 자동으로 열거하고 모든 정보를 저장하며 가능한 권한 상승 경로를 찾고 모든 정보를 그래프를 사용하여 보여줄 수 있는 놀라운 도구입니다.

Bloodhound는 **ingestors**와 **visualisation application**의 2가지 주요 부분으로 구성됩니다.

**ingestors**는 **도메인을 열거하고 모든 정보를 시각화 애플리케이션이 이해할 수 있는 형식으로 추출하는 데 사용됩니다.**

**visualisation application은 neo4j를 사용하여** 모든 정보가 어떻게 관련되어 있는지 보여주고 도메인에서 권한을 상승시키는 다양한 방법을 보여줍니다.

### Installation

BloodHound CE가 생성된 후, 전체 프로젝트는 Docker 사용의 용이성을 위해 업데이트되었습니다. 시작하는 가장 쉬운 방법은 미리 구성된 Docker Compose 구성을 사용하는 것입니다.

1. Docker Compose를 설치합니다. 이는 [Docker Desktop](https://www.docker.com/products/docker-desktop/) 설치에 포함되어야 합니다.
2. 실행:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Docker Compose의 터미널 출력에서 무작위로 생성된 비밀번호를 찾습니다.  
4. 브라우저에서 http://localhost:8080/ui/login으로 이동합니다. 사용자 이름으로 admin을 입력하고 로그에서 가져온 무작위로 생성된 비밀번호로 로그인합니다.  

이후 무작위로 생성된 비밀번호를 변경해야 하며, 새로운 인터페이스가 준비되어 ingestors를 직접 다운로드할 수 있습니다.  

### SharpHound  

여러 가지 옵션이 있지만, 도메인에 가입된 PC에서 현재 사용자로 SharpHound를 실행하고 모든 정보를 추출하려면 다음을 수행할 수 있습니다:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod** 및 루프 세션에 대한 자세한 내용은 [여기](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)에서 확인할 수 있습니다.

다른 자격 증명을 사용하여 SharpHound를 실행하려면 CMD netonly 세션을 생성하고 거기에서 SharpHound를 실행할 수 있습니다:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhound에 대해 더 알아보세요 ired.team에서.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r)는 **그룹 정책**과 관련된 Active Directory의 **취약점**을 찾기 위한 도구입니다. \
**도메인 사용자**를 사용하여 도메인 내의 호스트에서 **group3r를 실행**해야 합니다.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **는 AD 환경의 보안 태세를 평가**하고 멋진 **보고서**를 그래프와 함께 제공합니다.

실행하려면 이진 파일 `PingCastle.exe`를 실행하면 **옵션 메뉴**를 제공하는 **대화형 세션**이 시작됩니다. 기본 옵션은 **`healthcheck`**로, **도메인**의 **개요**를 설정하고 **구성 오류** 및 **취약점**을 찾습니다.&#x20;

{{#include ../../banners/hacktricks-training.md}}
